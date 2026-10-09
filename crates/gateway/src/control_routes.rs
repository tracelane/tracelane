//! `/v1/controls/*` — the workspace's own gateway controls: `OG-25` emergency controls
//! (pause, resume, revoke every key, block a model / provider / end user), the workspace
//! layer of the `OG-21`/`OG-22` policy, `OG-22` budget status and `OG-24` spend-alert
//! channels. Specs: `specs/OG-25-emergency-controls.md`, `specs/OG-24-spend-alerts.md`.
//!
//! | Route | Who |
//! |---|---|
//! | `GET /v1/controls`, `GET /v1/controls/budgets`, `GET /v1/controls/alert-channels`, `GET /v1/controls/alert-events` | any recognised session role, the self-host operator, or an API key with `read` |
//! | every write | a VERIFIED owner (session `owner`/`admin`) or the self-host operator — an API key never manages controls, so a leaked key cannot resume a workspace its owner paused |
//!
//! None of these routes runs the admission pipeline, so they keep working while the
//! workspace is paused (that is how it is resumed). Every write invalidates the tenant's
//! entitlement-cache entry after its commit, so the next inference request on this
//! gateway sees the change (one gateway per control plane, B-386).
//!
//! Tenant isolation: the tenant is `claims.tenant_id` ONLY, never a path or body field.
//! Mounted only with a Postgres control plane (`server.rs`).

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracelane_shared::TenantId;

use crate::db::controls::{Change, ControlsRow};
use crate::db::spend_alerts::{Channel, CreateOutcome, NewChannel, Sealed};

/// Storage seam — the routes are unit-tested without Postgres; the SQL is proven by the
/// real-Postgres suite. Off the hot path, so `async_trait` is fine.
#[async_trait::async_trait]
pub trait ControlStore: Send + Sync {
    async fn get(&self, tenant: &TenantId) -> anyhow::Result<ControlsRow>;
    async fn apply(
        &self,
        tenant: &TenantId,
        change: &Change,
        actor: &str,
    ) -> anyhow::Result<ControlsRow>;
    async fn revoke_all(&self, tenant: &TenantId, actor: &str) -> anyhow::Result<Vec<uuid::Uuid>>;
    async fn list_channels(&self, tenant: &TenantId) -> anyhow::Result<Vec<Channel>>;
    async fn create_channel(
        &self,
        tenant: &TenantId,
        new: &NewChannel,
        max: usize,
        actor: &str,
    ) -> anyhow::Result<CreateOutcome>;
    async fn delete_channel(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
    ) -> anyhow::Result<bool>;
    async fn get_sealed(&self, tenant: &TenantId, id: uuid::Uuid)
    -> anyhow::Result<Option<Sealed>>;
    async fn list_events(&self, tenant: &TenantId, limit: i64) -> anyhow::Result<Vec<Value>>;
}

/// The production store.
pub struct PgControlStore {
    pub pool: deadpool_postgres::Pool,
}

#[async_trait::async_trait]
impl ControlStore for PgControlStore {
    async fn get(&self, tenant: &TenantId) -> anyhow::Result<ControlsRow> {
        crate::db::controls::get(&self.pool, tenant).await
    }
    async fn apply(
        &self,
        tenant: &TenantId,
        change: &Change,
        actor: &str,
    ) -> anyhow::Result<ControlsRow> {
        crate::db::controls::apply(&self.pool, tenant, change, actor).await
    }
    async fn revoke_all(&self, tenant: &TenantId, actor: &str) -> anyhow::Result<Vec<uuid::Uuid>> {
        crate::db::api_keys::revoke_all_keys(&self.pool, tenant, actor).await
    }
    async fn list_channels(&self, tenant: &TenantId) -> anyhow::Result<Vec<Channel>> {
        crate::db::spend_alerts::list_channels(&self.pool, tenant).await
    }
    async fn create_channel(
        &self,
        tenant: &TenantId,
        new: &NewChannel,
        max: usize,
        actor: &str,
    ) -> anyhow::Result<CreateOutcome> {
        crate::db::spend_alerts::create_channel(&self.pool, tenant, new, max, actor).await
    }
    async fn delete_channel(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
    ) -> anyhow::Result<bool> {
        crate::db::spend_alerts::delete_channel(&self.pool, tenant, id, actor).await
    }
    async fn get_sealed(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
    ) -> anyhow::Result<Option<Sealed>> {
        crate::db::spend_alerts::get_sealed(&self.pool, tenant, id).await
    }
    async fn list_events(&self, tenant: &TenantId, limit: i64) -> anyhow::Result<Vec<Value>> {
        crate::db::spend_alerts::list_events(&self.pool, tenant, limit).await
    }
}

#[derive(Clone)]
pub struct ControlRoutesState {
    pub store: Arc<dyn ControlStore>,
    /// Invalidated after every write (`None` only in tests without a cache).
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
}

pub fn routes() -> Router<ControlRoutesState> {
    Router::new()
        .route("/v1/controls", get(get_handler))
        .route("/v1/controls/policy", put(policy_handler))
        .route("/v1/controls/pause", post(pause_handler))
        .route("/v1/controls/resume", post(resume_handler))
        .route("/v1/controls/blocks", put(blocks_handler))
        .route("/v1/controls/revoke-all-keys", post(revoke_all_handler))
        .route("/v1/controls/budgets", get(budgets_handler))
        .route(
            "/v1/controls/alert-channels",
            get(list_channels_handler).post(create_channel_handler),
        )
        .route(
            "/v1/controls/alert-channels/{id}",
            delete(delete_channel_handler),
        )
        .route(
            "/v1/controls/alert-channels/{id}/test",
            post(test_channel_handler),
        )
        .route("/v1/controls/alert-events", get(events_handler))
}

// ── Who may ─────────────────────────────────────────────────────────────────

/// READ: any recognised session role, the self-host operator, or an API key holding
/// `read`. Never mTLS. Fail-CLOSED.
fn can_read(claims: &crate::auth::Claims) -> bool {
    use crate::auth::AuthMethod;
    match claims.auth_method {
        AuthMethod::SelfHostMasterKey => true,
        AuthMethod::JwtBearer => claims.role.is_some(),
        AuthMethod::ApiKey => claims.allows_scope(crate::auth::scope::Scope::Read),
        AuthMethod::Mtls => false,
    }
}

fn json_error(status: StatusCode, code: &str, message: &str, field: Option<&str>) -> Response {
    crate::key_routes::json_error(status, code, message, field)
}

fn invalid(field: &str, message: impl Into<String>) -> Response {
    json_error(
        StatusCode::BAD_REQUEST,
        "invalid_field",
        &message.into(),
        Some(field),
    )
}

fn unavailable(what: &str) -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unavailable",
        &format!("failed to {what} — nothing was changed"),
        None,
    )
}

fn no_store(resp: impl IntoResponse) -> Response {
    let mut r = resp.into_response();
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    r
}

/// Authenticate. The tenant comes from these claims and nowhere else.
async fn authenticate(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let Some(raw) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing Authorization header",
            None,
        ));
    };
    crate::auth::validate_authorization(raw).await.map_err(|e| {
        let (status, message) = crate::auth::failure(&e);
        json_error(status, crate::auth::failure_code(&e), message, None)
    })
}

async fn reader(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let claims = authenticate(headers).await?;
    if !can_read(&claims) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "this credential cannot read workspace controls — it needs a workspace role, or \
             an API key with the `read` scope",
            None,
        ));
    }
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    Ok(claims)
}

/// An owner's claims plus the OG-35 actor `require_control` proved for this request.
/// Derefs to the claims, so `claims.tenant_id` / `&claims` read as before.
pub(crate) struct Owner {
    claims: crate::auth::Claims,
    audit: crate::db::control_audit::Actor,
}

impl std::ops::Deref for Owner {
    type Target = crate::auth::Claims;
    fn deref(&self) -> &crate::auth::Claims {
        &self.claims
    }
}

/// The owner gate, then the admin-plane gate (`OG-34` capability `cap`, `OG-36`
/// allowlist + SSO-required). The returned actor is what the store's audit row
/// carries (`OG-35`, via `control_audit::scoped` around the store call).
async fn owner(
    headers: &HeaderMap,
    cap: impl Into<crate::control_plane::ControlGate>,
) -> Result<Owner, Response> {
    let claims = authenticate(headers).await?;
    // A VERIFIED owner (session `owner`/`admin`) or the self-host operator — the same
    // rule as `project_routes::may_manage_governance`, stated here so the route-auth
    // guard can see it. Never an API key.
    let operator = matches!(
        claims.auth_method,
        crate::auth::AuthMethod::SelfHostMasterKey
    );
    if !(claims.is_verified_owner() || operator) {
        return Err(crate::key_routes::role_forbidden("owner"));
    }
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let control = crate::control_plane::require_control(&claims, cap, headers)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok(Owner {
        claims,
        audit: control.audit,
    })
}

/// A JSON OBJECT body as `T` (an empty body reads as `{}`).
fn object_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Box<Response>> {
    let v: Result<Value, _> = if body.iter().all(u8::is_ascii_whitespace) {
        Ok(json!({}))
    } else {
        serde_json::from_slice(body)
    };
    v.and_then(|v| {
        if v.is_object() {
            serde_json::from_value(v)
        } else {
            Err(serde::de::Error::custom("expected a JSON object"))
        }
    })
    .map_err(|e| {
        Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            &format!("the body must be a JSON object: {e}"),
            None,
        ))
    })
}

async fn invalidate(state: &ControlRoutesState, tenant: &TenantId) {
    if let Some(cache) = &state.entitlements {
        cache.invalidate(*tenant.as_uuid()).await;
    }
}

// ── Controls ────────────────────────────────────────────────────────────────

/// `GET /v1/controls`.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn get_handler(State(state): State<ControlRoutesState>, headers: HeaderMap) -> Response {
    let claims = match reader(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.store.get(&claims.tenant_id).await {
        Ok(row) => no_store(Json(row.to_json())),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "controls read failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to read the workspace controls",
                None,
            )
        }
    }
}

async fn write(state: &ControlRoutesState, claims: &Owner, change: Change, what: &str) -> Response {
    match crate::db::control_audit::scoped(
        claims.audit.clone(),
        state.store.apply(&claims.tenant_id, &change, &claims.sub),
    )
    .await
    {
        Ok(row) => {
            invalidate(state, &claims.tenant_id).await;
            no_store(Json(row.to_json()))
        }
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "controls write failed");
            unavailable(what)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBody {
    policy: Value,
}

/// `OG-21`/`OG-22`: validate the WORKSPACE policy (limits, budget, end_user_budget only).
pub(crate) fn validate_workspace_policy(v: &Value) -> Result<Option<Value>, Box<Response>> {
    if v.is_null() {
        return Ok(None);
    }
    let canonical =
        crate::project_routes::validate_policy(v).map_err(|e| Box::new(e.response()))?;
    let parsed = tracelane_shared::key_policy::KeyPolicy::parse(&canonical, None)
        .map_err(|e| Box::new(invalid("policy", e.message)))?;
    parsed
        .workspace_only()
        .map_err(|e| Box::new(invalid(&format!("policy.{}", e.field), e.message)))?;
    Ok(Some(canonical))
}

/// `PUT /v1/controls/policy` `{policy: {…} | null}`.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn policy_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let claims = match owner(
        &headers,
        crate::auth::capability::Capability::ManageControls,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body: PolicyBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let policy = match validate_workspace_policy(&body.policy) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    write(
        &state,
        &claims,
        Change::Policy(policy),
        "update the workspace policy",
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PauseBody {
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /v1/controls/pause` `{reason?}` — every inference route answers `423
/// workspace_paused` until resumed. Idempotent.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn pause_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // rev6 N1: an incident control — its own per-principal bucket.
    let claims = match owner(
        &headers,
        crate::control_plane::incident(crate::auth::capability::Capability::ManageControls),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body: PauseBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let max = crate::controls::config().max_pause_reason_chars;
    let reason = body
        .reason
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty());
    if let Some(r) = &reason
        && (r.chars().count() > max || r.chars().any(char::is_control))
    {
        return invalid(
            "reason",
            format!("at most {max} characters, no control characters"),
        );
    }
    write(
        &state,
        &claims,
        Change::Pause { reason },
        "pause the workspace",
    )
    .await
}

/// `POST /v1/controls/resume`.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn resume_handler(State(state): State<ControlRoutesState>, headers: HeaderMap) -> Response {
    // rev6 N1: an incident control — its own per-principal bucket.
    let claims = match owner(
        &headers,
        crate::control_plane::incident(crate::auth::capability::Capability::ManageControls),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    write(&state, &claims, Change::Resume, "resume the workspace").await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BlocksBody {
    #[serde(default)]
    models: Option<Vec<String>>,
    #[serde(default)]
    providers: Option<Vec<String>>,
    #[serde(default)]
    end_users: Option<Vec<String>>,
}

fn block_list(
    field: &str,
    raw: Option<Vec<String>>,
    norm: fn(&str) -> Option<String>,
) -> Result<Option<Vec<String>>, Box<Response>> {
    let Some(raw) = raw else { return Ok(None) };
    let max = crate::controls::config().max_block_entries;
    if raw.len() > max {
        return Err(Box::new(invalid(field, format!("at most {max} entries"))));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for e in raw {
        let Some(n) = norm(&e) else {
            let shown: String = e.chars().take(64).collect();
            return Err(Box::new(invalid(
                field,
                format!("`{shown}` is not a valid entry"),
            )));
        };
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(Some(out))
}

fn norm_model(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    (!s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@*-".contains(&b)))
    .then_some(s)
}

fn norm_provider(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    (!s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
    .then_some(s)
}

fn norm_end_user(s: &str) -> Option<String> {
    // The OBS-20 bound: an end-user id the gateway would record is at most 256 bytes.
    (!s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)).then(|| s.to_owned())
}

/// `PUT /v1/controls/blocks` `{models?, providers?, endUsers?}` — each list given
/// REPLACES that list; an omitted list is unchanged; `[]` clears it.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn blocks_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // rev6 N1: an incident control (block the model / provider / end user that is the
    // incident) — its own per-principal bucket.
    let claims = match owner(
        &headers,
        crate::control_plane::incident(crate::auth::capability::Capability::ManageControls),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body: BlocksBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let change = (|| {
        Ok::<_, Box<Response>>(Change::Blocks {
            models: block_list("models", body.models, norm_model)?,
            providers: block_list("providers", body.providers, norm_provider)?,
            end_users: block_list("endUsers", body.end_users, norm_end_user)?,
        })
    })();
    match change {
        Ok(c) => write(&state, &claims, c, "update the block lists").await,
        Err(r) => *r,
    }
}

/// The phrase `POST /v1/controls/revoke-all-keys` requires.
pub(crate) const REVOKE_ALL_CONFIRM: &str = "revoke all keys";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeAllBody {
    #[serde(default)]
    confirm: Option<String>,
}

/// `POST /v1/controls/revoke-all-keys` `{confirm: "revoke all keys"}` — irreversible.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn revoke_all_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // rev6 N1: an incident control — its own per-principal bucket.
    let claims = match owner(
        &headers,
        crate::control_plane::incident(crate::auth::capability::Capability::ManageAllKeys),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body: RevokeAllBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    if body.confirm.as_deref() != Some(REVOKE_ALL_CONFIRM) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "confirmation_required",
            &format!(
                "revoking every API key cannot be undone — send {{\"confirm\": \
                 \"{REVOKE_ALL_CONFIRM}\"}}"
            ),
            Some("confirm"),
        );
    }
    match crate::db::control_audit::scoped(
        claims.audit.clone(),
        state.store.revoke_all(&claims.tenant_id, &claims.sub),
    )
    .await
    {
        Ok(ids) => no_store(Json(json!({
            "revoked": ids.len(),
            "keyIds": ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }))),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "revoke-all failed");
            unavailable("revoke the keys")
        }
    }
}

/// `GET /v1/controls/budgets` — this gateway's live `OG-22` budget counters.
#[tracing::instrument(skip(headers), fields(tenant_id = tracing::field::Empty))]
async fn budgets_handler(headers: HeaderMap) -> Response {
    let claims = match reader(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let budgets = crate::budgets::table().snapshot(*claims.tenant_id.as_uuid(), chrono::Utc::now());
    no_store(Json(json!({ "budgets": budgets })))
}

// ── OG-24 alert channels ────────────────────────────────────────────────────

/// `full`: the caller may manage channels (an admin) and sees the stored target; anyone
/// else — every role and a `read` key may LIST channels — sees a webhook's host only
/// (rev5 L4: its path / query can carry the receiver's token).
fn channel_view(c: &Channel, full: bool) -> Value {
    let target = if full {
        c.target.clone()
    } else {
        crate::db::spend_alerts::redacted_target(&c.kind, &c.target)
    };
    json!({
        "id": c.id.to_string(),
        "kind": c.kind,
        "name": c.name,
        "target": target,
        "createdAt": c.created_at.to_rfc3339(),
    })
}

/// `GET /v1/controls/alert-channels`.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn list_channels_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
) -> Response {
    let claims = match reader(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let full = claims.can(crate::auth::capability::Capability::ManageControls);
    match state.store.list_channels(&claims.tenant_id).await {
        Ok(list) => no_store(Json(json!({
            "channels": list.iter().map(|c| channel_view(c, full)).collect::<Vec<_>>()
        }))),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "alert channel list failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to read the alert channels",
                None,
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelBody {
    kind: String,
    name: String,
    target: String,
}

fn valid_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && s.len() <= 254
        && s.matches('@').count() == 1
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == ',' || c == ';')
}

/// `POST /v1/controls/alert-channels` `{kind, name, target}`. A `webhook` returns its
/// `signingSecret` ONCE.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn create_channel_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    use secrecy::ExposeSecret as _;
    let claims = match owner(
        &headers,
        crate::auth::capability::Capability::ManageControls,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body: ChannelBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let name = body.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
        return invalid("name", "name must be 1-128 characters");
    }
    let target = body.target.trim().to_owned();
    let id = uuid::Uuid::new_v4();
    let tenant = *claims.tenant_id.as_uuid();
    let (kind, stored_target, secret): (&'static str, String, Option<secrecy::SecretString>) =
        match body.kind.as_str() {
            "email" => {
                if !valid_email(&target) {
                    return invalid(
                        "target",
                        "an email channel's target must be one email address",
                    );
                }
                ("email", target, None)
            }
            "slack" | "webhook" => {
                if !target.starts_with("https://") {
                    return invalid("target", "the URL must be https://");
                }
                if let Err(e) = crate::ssrf_guard::validate_url(&target).await {
                    return invalid(
                        "target",
                        format!(
                            "the URL is not allowed (private, loopback or metadata address): {e}"
                        ),
                    );
                }
                if body.kind == "slack" {
                    let shown = crate::alerts::routes::redact_destination_url(&target);
                    ("slack", shown, Some(secrecy::SecretString::from(target)))
                } else {
                    match crate::spend_alerts::new_signing_secret() {
                        Ok(s) => ("webhook", target, Some(s)),
                        Err(_) => return unavailable("create the channel"),
                    }
                }
            }
            _ => return invalid("kind", "kind must be email, slack or webhook"),
        };
    let secret_enc = match &secret {
        None => None,
        Some(s) => {
            let Some(mk) = crate::byok::master_key() else {
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "encryption_unavailable",
                    "this gateway has no BYOK master key, so it cannot store a channel secret \
                     — the secret is never stored in clear",
                    None,
                );
            };
            match mk.encrypt_with_context(s, &crate::spend_alerts::channel_aad(tenant, id)) {
                Ok(c) => Some(c),
                Err(_) => return unavailable("create the channel"),
            }
        }
    };
    let new = NewChannel {
        id,
        kind,
        name,
        target: stored_target,
        secret_enc,
    };
    let max = crate::controls::config().max_alert_channels_per_tenant;
    match crate::db::control_audit::scoped(
        claims.audit.clone(),
        state
            .store
            .create_channel(&claims.tenant_id, &new, max, &claims.sub),
    )
    .await
    {
        Ok(CreateOutcome::Created(c)) => {
            let mut v = channel_view(&c, true);
            if kind == "webhook"
                && let Some(s) = &secret
            {
                v["signingSecret"] = json!(s.expose_secret());
            }
            no_store((StatusCode::CREATED, Json(v)))
        }
        Ok(CreateOutcome::LimitReached { max }) => json_error(
            StatusCode::CONFLICT,
            "channel_limit_reached",
            &format!("this workspace already has {max} alert channels — delete one first"),
            None,
        ),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "alert channel create failed");
            unavailable("create the channel")
        }
    }
}

fn channel_not_found() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "channel_not_found",
        "alert channel not found",
        None,
    )
}

/// `DELETE /v1/controls/alert-channels/{id}`.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn delete_channel_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let claims = match owner(
        &headers,
        crate::auth::capability::Capability::ManageControls,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return channel_not_found();
    };
    match crate::db::control_audit::scoped(
        claims.audit.clone(),
        state
            .store
            .delete_channel(&claims.tenant_id, id, &claims.sub),
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => channel_not_found(),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "alert channel delete failed");
            unavailable("delete the channel")
        }
    }
}

/// `POST /v1/controls/alert-channels/{id}/test` — one synchronous delivery.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn test_channel_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let claims = match owner(
        &headers,
        crate::auth::capability::Capability::ManageControls,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return channel_not_found();
    };
    // rev5 L5: a test is a real outbound delivery (an email, a Slack post, a signed
    // webhook) — its own per-workspace bucket, so an admin plane cannot be used as a
    // relay to hammer a receiver.
    if let Err(r) = crate::control_plane::charge_channel_test(&claims.tenant_id) {
        return r.into_response();
    }
    let ch = match state.store.get_sealed(&claims.tenant_id, id).await {
        Ok(Some(c)) => c,
        Ok(None) => return channel_not_found(),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "alert channel read failed");
            return unavailable("read the channel");
        }
    };
    let payload = json!({
        "type": "budget.test",
        "tenant_id": claims.tenant_id.to_string(),
        "policy": "workspace", "scope": "workspace", "threshold": "test",
        "window": "monthly", "mode": "soft", "budget_usd": 0.0, "spent_usd": 0.0,
    });
    let mail = crate::spend_alerts::Mail::from_env();
    match crate::spend_alerts::deliver(&mail, &ch, uuid::Uuid::new_v4(), &payload).await {
        Ok(()) => no_store(Json(json!({ "delivered": true }))),
        Err(e) => no_store((
            StatusCode::BAD_GATEWAY,
            Json(
                json!({ "delivered": false, "error": "delivery_failed", "message": e.to_string() }),
            ),
        )),
    }
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    limit: Option<i64>,
}

/// `GET /v1/controls/alert-events?limit=` — the most recent deliveries (≤ 200).
#[tracing::instrument(skip(state, headers, q), fields(tenant_id = tracing::field::Empty))]
async fn events_handler(
    State(state): State<ControlRoutesState>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Response {
    let claims = match reader(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    match state.store.list_events(&claims.tenant_id, limit).await {
        Ok(events) => no_store(Json(json!({ "events": events }))),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "alert events read failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to read the alert events",
                None,
            )
        }
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, Claims, Role};
    use crate::handler_harness::{authed, body_json};
    use std::sync::Mutex;

    /// An in-memory store: one tenant's row, its channels, revoked count.
    #[derive(Default)]
    struct Mem {
        row: Mutex<ControlsRow>,
        channels: Mutex<Vec<Channel>>,
        revoked: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl ControlStore for Mem {
        async fn get(&self, _t: &TenantId) -> anyhow::Result<ControlsRow> {
            Ok(self.row.lock().unwrap().clone())
        }
        async fn apply(
            &self,
            _t: &TenantId,
            change: &Change,
            actor: &str,
        ) -> anyhow::Result<ControlsRow> {
            let mut r = self.row.lock().unwrap();
            match change {
                Change::Policy(p) => r.policy.clone_from(p),
                Change::Pause { reason } => {
                    if r.paused_at.is_none() {
                        r.paused_at = Some(chrono::Utc::now());
                        r.paused_by = Some(actor.to_owned());
                        r.pause_reason.clone_from(reason);
                    }
                }
                Change::Resume => {
                    r.paused_at = None;
                    r.paused_by = None;
                    r.pause_reason = None;
                }
                Change::Blocks {
                    models,
                    providers,
                    end_users,
                } => {
                    if let Some(m) = models {
                        r.blocked_models.clone_from(m);
                    }
                    if let Some(p) = providers {
                        r.blocked_providers.clone_from(p);
                    }
                    if let Some(u) = end_users {
                        r.blocked_end_users.clone_from(u);
                    }
                }
            }
            Ok(r.clone())
        }
        async fn revoke_all(&self, _t: &TenantId, _a: &str) -> anyhow::Result<Vec<uuid::Uuid>> {
            *self.revoked.lock().unwrap() += 1;
            Ok(vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()])
        }
        async fn list_channels(&self, _t: &TenantId) -> anyhow::Result<Vec<Channel>> {
            Ok(self.channels.lock().unwrap().clone())
        }
        async fn create_channel(
            &self,
            _t: &TenantId,
            new: &NewChannel,
            max: usize,
            _a: &str,
        ) -> anyhow::Result<CreateOutcome> {
            let mut v = self.channels.lock().unwrap();
            if v.len() >= max {
                return Ok(CreateOutcome::LimitReached { max });
            }
            let c = Channel {
                id: new.id,
                kind: new.kind.to_owned(),
                name: new.name.clone(),
                target: new.target.clone(),
                created_at: chrono::Utc::now(),
            };
            v.push(c.clone());
            Ok(CreateOutcome::Created(c))
        }
        async fn delete_channel(
            &self,
            _t: &TenantId,
            id: uuid::Uuid,
            _a: &str,
        ) -> anyhow::Result<bool> {
            let mut v = self.channels.lock().unwrap();
            let n = v.len();
            v.retain(|c| c.id != id);
            Ok(v.len() != n)
        }
        async fn get_sealed(
            &self,
            _t: &TenantId,
            _id: uuid::Uuid,
        ) -> anyhow::Result<Option<Sealed>> {
            Ok(None)
        }
        async fn list_events(&self, _t: &TenantId, _l: i64) -> anyhow::Result<Vec<Value>> {
            Ok(vec![])
        }
    }

    type Resolved = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = anyhow::Result<crate::entitlement_cache::ResolvedEntitlements>,
                > + Send,
        >,
    >;

    /// The routes AND an entitlement cache that resolves from the same memory store — so a
    /// write through a route reaches admission exactly as the Postgres path does.
    fn wired() -> (ControlRoutesState, Arc<Mem>) {
        let mem = Arc::new(Mem::default());
        let m2 = Arc::clone(&mem);
        let cache = Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
            move |_t| {
                let r = m2.row.lock().unwrap().clone();
                Box::pin(async move {
                    Ok(crate::entitlement_cache::ResolvedEntitlements {
                        controls: Arc::new(crate::controls::WorkspaceControls::from_row(
                            r.policy.as_ref(),
                            r.paused_at.map(|at| crate::controls::Pause {
                                at,
                                by: r.paused_by,
                                reason: r.pause_reason,
                            }),
                            r.blocked_models,
                            r.blocked_providers,
                            r.blocked_end_users,
                        )),
                        rate_limit_rpm: None,
                        ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
                    })
                }) as Resolved
            },
        )));
        (
            ControlRoutesState {
                store: mem.clone(),
                entitlements: Some(cache),
            },
            mem,
        )
    }

    fn owner_claims() -> Claims {
        crate::auth::dev_stub_claims(AuthMethod::JwtBearer)
    }

    fn with_role(role: Option<Role>, method: AuthMethod) -> Claims {
        let mut c = crate::auth::dev_stub_claims(method);
        c.role = role;
        c
    }

    fn bytes(v: Value) -> axum::body::Bytes {
        axum::body::Bytes::from(serde_json::to_vec(&v).unwrap())
    }

    /// OG-36 on the OG-21/22/24/25 routes: an OWNER outside the workspace's admin IP
    /// allowlist (here: an address that cannot be proven — no B-594 layer), or on a
    /// non-SSO session under SSO-required, is refused on EVERY write, and nothing is
    /// written.
    #[tokio::test]
    async fn og36_the_admin_plane_gate_covers_every_controls_write() {
        use crate::control_plane::test_overrides;
        use crate::db::admin_security::AdminAccess;
        let policies = [
            (
                AdminAccess {
                    admin_ip_allowlist: vec!["203.0.113.0/24".into()],
                    ..AdminAccess::default()
                },
                None,
                "admin_ip_not_allowed",
            ),
            (
                AdminAccess {
                    sso_required: true,
                    ..AdminAccess::default()
                },
                Some(Ok(false)),
                "sso_required",
            ),
        ];
        for (access, sso, code) in policies {
            let (st, mem) = wired();
            let _c = crate::auth::test_claims::Guard::set(owner_claims());
            let _g = test_overrides::Guard::new(Some(Ok(access)), sso, None);
            let s = State(st.clone());
            let rs = vec![
                policy_handler(s.clone(), authed(), bytes(json!({"policy": null}))).await,
                pause_handler(s.clone(), authed(), bytes(json!({}))).await,
                resume_handler(s.clone(), authed()).await,
                blocks_handler(s.clone(), authed(), bytes(json!({"models": ["x"]}))).await,
                revoke_all_handler(
                    s.clone(),
                    authed(),
                    bytes(json!({"confirm": REVOKE_ALL_CONFIRM})),
                )
                .await,
                create_channel_handler(
                    s.clone(),
                    authed(),
                    bytes(json!({"kind": "email", "name": "n", "target": "a@b.co"})),
                )
                .await,
                delete_channel_handler(s.clone(), authed(), Path(uuid::Uuid::new_v4().to_string()))
                    .await,
            ];
            for r in rs {
                assert_eq!(r.status(), StatusCode::FORBIDDEN);
                let v = body_json(r).await;
                assert_eq!(v["error"], code, "{v}");
            }
            assert_eq!(*mem.revoked.lock().unwrap(), 0, "nothing revoked");
            assert!(mem.channels.lock().unwrap().is_empty(), "nothing created");
            assert!(mem.row.lock().unwrap().paused_at.is_none(), "not paused");
        }
    }

    /// PROOF 5: a member, a viewer and an API key are refused on EVERY write.
    #[tokio::test]
    async fn og25_only_an_owner_writes_controls() {
        let (st, mem) = wired();
        for c in [
            with_role(Some(Role::Member), AuthMethod::JwtBearer),
            with_role(Some(Role::Viewer), AuthMethod::JwtBearer),
            with_role(None, AuthMethod::ApiKey),
        ] {
            let _g = crate::auth::test_claims::Guard::set(c);
            let s = State(st.clone());
            let rs = vec![
                policy_handler(s.clone(), authed(), bytes(json!({"policy": null}))).await,
                pause_handler(s.clone(), authed(), bytes(json!({}))).await,
                resume_handler(s.clone(), authed()).await,
                blocks_handler(s.clone(), authed(), bytes(json!({"models": ["x"]}))).await,
                revoke_all_handler(
                    s.clone(),
                    authed(),
                    bytes(json!({"confirm": REVOKE_ALL_CONFIRM})),
                )
                .await,
                create_channel_handler(
                    s.clone(),
                    authed(),
                    bytes(json!({"kind": "email", "name": "n", "target": "a@b.co"})),
                )
                .await,
                delete_channel_handler(s.clone(), authed(), Path(uuid::Uuid::new_v4().to_string()))
                    .await,
            ];
            for r in rs {
                assert_eq!(r.status(), StatusCode::FORBIDDEN);
            }
        }
        assert!(mem.row.lock().unwrap().paused_at.is_none());
        assert_eq!(*mem.revoked.lock().unwrap(), 0);
    }

    /// PROOF 2: pause → inference 423 while the control routes keep answering → resume →
    /// inference admitted again. Propagation is the route's own cache invalidation.
    #[tokio::test]
    async fn og25_pause_stops_inference_but_not_the_control_routes() {
        let (st, _mem) = wired();
        let mut state = crate::handler_harness::test_state(
            crate::providers::ProviderRegistry::new().expect("registry"),
        );
        state.entitlements = st.entitlements.clone();
        let _g = crate::auth::test_claims::Guard::set(owner_claims());
        assert!(admit(&state).await.is_ok(), "not paused yet");

        let r = pause_handler(
            State(st.clone()),
            authed(),
            bytes(json!({"reason": "incident"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await["paused"], json!(true));
        let refused = admit(&state).await;
        assert!(
            matches!(&refused, Err(crate::admission::Refusal::Control(c)) if c.code == "workspace_paused"),
            "{refused:?}"
        );
        // The control plane still answers while paused.
        let r = get_handler(State(st.clone()), authed()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await["pauseReason"], json!("incident"));
        let r = resume_handler(State(st.clone()), authed()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(admit(&state).await.is_ok(), "resumed");
    }

    async fn admit(state: &crate::server::AppState) -> Result<(), crate::admission::Refusal> {
        let body = json!({"model": "ollama/llama3", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]});
        crate::key_policy_route_tests::run_with::<crate::admission::Chat>(
            state,
            &authed(),
            body,
            owner_claims(),
        )
        .await
    }

    #[tokio::test]
    async fn og25_revoke_all_needs_the_confirmation_phrase() {
        let (st, mem) = wired();
        let _g = crate::auth::test_claims::Guard::set(owner_claims());
        let r = revoke_all_handler(State(st.clone()), authed(), bytes(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(r).await["error"], json!("confirmation_required"));
        assert_eq!(*mem.revoked.lock().unwrap(), 0);
        let r = revoke_all_handler(
            State(st),
            authed(),
            bytes(json!({"confirm": "revoke all keys"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await["revoked"], json!(2));
        assert_eq!(*mem.revoked.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn og25_blocks_and_the_workspace_policy_are_validated() {
        let (st, mem) = wired();
        let _g = crate::auth::test_claims::Guard::set(owner_claims());
        let r = blocks_handler(
            State(st.clone()),
            authed(),
            bytes(json!({"models": ["GPT-4o*", "gpt-4o*"], "endUsers": ["mallory"]})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            mem.row.lock().unwrap().blocked_models,
            vec!["gpt-4o*".to_string()]
        );
        let r = blocks_handler(
            State(st.clone()),
            authed(),
            bytes(json!({"providers": ["bad provider"]})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        // A workspace policy may carry limits, budgets, models, providers and source_ips
        // (rev5 M6) — never a per-integration cap.
        let r = policy_handler(
            State(st.clone()),
            authed(),
            bytes(json!({"policy": {"max_output_tokens": 5}})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(r).await["field"],
            json!("policy.max_output_tokens")
        );
        let r = policy_handler(
            State(st.clone()),
            authed(),
            bytes(
                json!({"policy": {"limits": {"tpm": 1000}, "budget": {"usd": 50, "mode": "soft"}}}),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            mem.row.lock().unwrap().policy.as_ref().unwrap()["budget"]["mode"],
            json!("soft")
        );
    }

    /// OG-24 PROOF 3 (create half): a private / loopback / metadata URL is refused at
    /// create; http:// is refused; an email channel is accepted.
    #[tokio::test]
    async fn og24_a_private_channel_url_is_refused_at_create() {
        let (st, mem) = wired();
        let _g = crate::auth::test_claims::Guard::set(owner_claims());
        for (kind, url) in [
            ("webhook", "https://127.0.0.1/hook"),
            ("webhook", "https://169.254.169.254/latest"),
            ("slack", "https://10.1.2.3/services/x"),
            ("webhook", "http://example.com/hook"),
        ] {
            let r = create_channel_handler(
                State(st.clone()),
                authed(),
                bytes(json!({"kind": kind, "name": "n", "target": url})),
            )
            .await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{url}");
            assert_eq!(body_json(r).await["field"], json!("target"), "{url}");
        }
        assert!(mem.channels.lock().unwrap().is_empty());
        let r = create_channel_handler(
            State(st.clone()),
            authed(),
            bytes(json!({"kind": "email", "name": "ops", "target": "ops@example.com"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CREATED);
        let r = create_channel_handler(
            State(st),
            authed(),
            bytes(json!({"kind": "email", "name": "x", "target": "not-an-email"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// rev5 L4: a webhook channel's URL (its path / query can carry the receiver's token)
    /// is shown to an admin only; every other reader sees the host, and so does the
    /// control-change trail (`spend_alerts::redacted_target`, used by both).
    #[tokio::test]
    async fn rev5_l4_a_webhook_url_is_host_only_to_non_admins() {
        let (st, mem) = wired();
        mem.channels.lock().unwrap().push(Channel {
            id: uuid::Uuid::new_v4(),
            kind: "webhook".into(),
            name: "ops".into(),
            target: "https://user:pw@hooks.example.com:8443/in/s3cr3t-token?sig=abc".into(),
            created_at: chrono::Utc::now(),
        });
        let viewer = Claims {
            role: Some(Role::Viewer),
            ..owner_claims()
        };
        let _g = crate::auth::test_claims::Guard::set(viewer);
        let v = body_json(list_channels_handler(State(st.clone()), authed()).await).await;
        let shown = v["channels"][0]["target"].as_str().unwrap().to_owned();
        assert_eq!(shown, "https://hooks.example.com:8443/…");
        drop(_g);
        let _g = crate::auth::test_claims::Guard::set(owner_claims());
        let v = body_json(list_channels_handler(State(st), authed()).await).await;
        assert!(
            v["channels"][0]["target"]
                .as_str()
                .unwrap()
                .contains("s3cr3t-token"),
            "an admin manages the channel and sees it whole"
        );
        assert_eq!(
            crate::db::spend_alerts::redacted_target("email", "ops@example.com"),
            "ops@example.com"
        );
        assert_eq!(
            crate::db::spend_alerts::redacted_target("webhook", "not a url"),
            "…"
        );
    }

    /// rev5 L5: the channel-test endpoint (one real outbound delivery per call) has its own
    /// per-workspace bucket; past it, 429 `control_rate_limited` before any delivery.
    #[tokio::test]
    async fn rev5_l5_channel_tests_are_throttled() {
        let (st, _) = wired();
        let _g = crate::auth::test_claims::Guard::set(owner_claims());
        let _r = crate::control_plane::test_overrides::RateGuard::set3(1_000, 1_000, 2);
        let id = uuid::Uuid::new_v4().to_string();
        let mut statuses = Vec::new();
        for _ in 0..3 {
            let r = test_channel_handler(State(st.clone()), authed(), Path(id.clone())).await;
            statuses.push(r.status());
        }
        assert_eq!(
            statuses,
            vec![
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );
    }

    /// rev6 N1, through the REAL handlers: an owner whose shared admin-plane bucket is
    /// spent (here by their own policy edits) can still pause, block, resume and revoke
    /// every key — the incident controls draw on their own bucket. RED before the fix:
    /// one per-workspace bucket, so pause answered 429.
    #[tokio::test]
    async fn rev6_n1_incident_controls_work_after_the_shared_bucket_is_spent() {
        let (st, mem) = wired();
        let owner = Claims {
            tenant_id: TenantId::from_jwt_claim(uuid::Uuid::new_v4()),
            ..owner_claims()
        };
        let _g = crate::auth::test_claims::Guard::set(owner);
        let _r = crate::control_plane::test_overrides::RateGuard::set4(2, 1_000, 1_000, 1_000);
        for _ in 0..2 {
            let r =
                policy_handler(State(st.clone()), authed(), bytes(json!({"policy": null}))).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let r = policy_handler(State(st.clone()), authed(), bytes(json!({"policy": null}))).await;
        assert_eq!(
            r.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the shared bucket is spent"
        );

        let r = pause_handler(
            State(st.clone()),
            authed(),
            bytes(json!({"reason": "incident"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "pause");
        let r = blocks_handler(
            State(st.clone()),
            authed(),
            bytes(json!({"models": ["gpt-4o*"]})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "blocks");
        let r = resume_handler(State(st.clone()), authed()).await;
        assert_eq!(r.status(), StatusCode::OK, "resume");
        let r = revoke_all_handler(
            State(st),
            authed(),
            bytes(json!({"confirm": REVOKE_ALL_CONFIRM})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "revoke-all");
        assert_eq!(*mem.revoked.lock().unwrap(), 1);
    }
}
