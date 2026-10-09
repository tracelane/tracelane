//! Customer-facing API-key mint endpoint.
//!
//! `POST /v1/keys` — mints a `tlane_<base62>` API key for the authenticated
//! tenant and returns the raw key exactly once. Mounted only when Postgres is
//! configured (`crate::db::global_pool().is_some()`), alongside the BYOK and
//! prompt-management routes.
//!
//! ## Why the gateway mints (not the dashboard)
//!
//! The dashboard runs on the Cloudflare Workers runtime, where the web minter's
//! WASM Argon2 (`hash-wasm`) fails at runtime — every "+ New key" click 500'd
//! . Minting here runs RustCrypto Argon2 natively and reuses the exact
//! same peppered-HMAC + Argon2id derivation as the verifier
//! (`crate::db::api_keys`), so keys stay byte-compatible: a key minted here
//! verifies through `lookup_tenant_by_key_body` unchanged, and any key minted by
//! the legacy web path (non-CF deploys) stays valid too.
//!
//! ## Tenant isolation
//!
//! The tenant id is sourced ONLY from `Claims.tenant_id`
//! (`crate::auth::validate_authorization`) — never a path, query, or body field.
//! The dashboard proxies the end-user's WorkOS JWT here; the JWT `org_id` →
//! internal-UUID bridge (ADR-042) yields the tenant the row is inserted under.

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::api_keys::{KeyEditor, KeyPatch, KeyRecord, MintedKey, UpdateOutcome};
use tracelane_shared::TenantId;

/// Upper bound on the user-supplied key name (defensive; the column is TEXT).
const MAX_KEY_NAME_LEN: usize = 128;

/// Mint seam — lets the handler be unit-tested without Postgres (real impl is
/// [`PgKeyMinter`]; tests use an in-module mock). Off the request hot path, so
/// `async_trait` is fine — CLAUDE.md bans it only on the gateway hot path.
#[async_trait::async_trait]
pub trait KeyMinter: Send + Sync {
    async fn rotation_grace_hours(&self) -> Result<i64>;
    async fn rotate(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
        grace_hours: i64,
    ) -> Result<Option<crate::db::api_keys::RotatedKey>>;
    /// Mint a key for `tenant`, returning the row plus the one-time raw secret.
    /// `minted_by` is the WorkOS user id of the minting user (for §3
    /// key-revoke-on-member-removal); `None` for API-key / service auth.
    async fn mint(
        &self,
        tenant: &TenantId,
        name: &str,
        minted_by: Option<&str>,
        opts: crate::db::api_keys::MintOptions,
    ) -> Result<MintedKey>;
    /// SET-38 — one key of `tenant`; `None` if absent or revoked.
    async fn get_key(&self, tenant: &TenantId, id: uuid::Uuid) -> Result<Option<KeyRecord>>;
    /// SET-38 — edit in place; authorization is enforced under the row lock.
    async fn update_key(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        editor: KeyEditor<'_>,
        patch: &KeyPatch,
        actor: &str,
    ) -> Result<UpdateOutcome>;
    /// B-586 — revoke through the gateway, invalidating the auth cache.
    async fn revoke_key(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>>;
    /// This key's recorded spend in its current budget window. `None` when it
    /// cannot be read — NEVER `Some(0.0)` for "unknown".
    async fn recorded_spend(
        &self,
        tenant: &TenantId,
        key_id: uuid::Uuid,
        cadence: crate::spend::BudgetReset,
    ) -> Option<f64>;
}

/// OG-35: the full request actor the handler scoped
/// (`control_audit::scoped`, after `require_control`), else the `sub` the trait
/// passed as a system actor. Either way the store RECORDS; only the request id,
/// role and address depend on the scope.
pub(crate) fn audit_actor(sub: &str) -> crate::db::control_audit::Actor {
    crate::db::control_audit::current()
        .unwrap_or_else(|| crate::db::control_audit::Actor::system(sub))
}

/// Production minter — inserts through the shared Postgres pool.
pub struct PgKeyMinter {
    pub pool: deadpool_postgres::Pool,
    /// ClickHouse for `recorded_usd`; `None` ⇒ the spend is reported unknown.
    pub ch_url: Option<String>,
    /// For the ADR-031 read caps at the tenant's own tier.
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
}

#[async_trait::async_trait]
impl KeyMinter for PgKeyMinter {
    async fn rotation_grace_hours(&self) -> Result<i64> {
        crate::db::api_keys::rotation_grace_hours(&self.pool).await
    }
    async fn rotate(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
        grace_hours: i64,
    ) -> Result<Option<crate::db::api_keys::RotatedKey>> {
        let actor = audit_actor(actor);
        crate::db::api_keys::rotate(&self.pool, tenant, id, &actor, grace_hours).await
    }
    async fn mint(
        &self,
        tenant: &TenantId,
        name: &str,
        minted_by: Option<&str>,
        opts: crate::db::api_keys::MintOptions,
    ) -> Result<MintedKey> {
        match crate::db::control_audit::current() {
            Some(actor) => {
                crate::db::api_keys::mint_as(&self.pool, tenant, name, minted_by, opts, &actor)
                    .await
            }
            // No request scope: still recorded, as the minter (`mint`'s system actor).
            None => crate::db::api_keys::mint(&self.pool, tenant, name, minted_by, opts).await,
        }
    }
    async fn get_key(&self, tenant: &TenantId, id: uuid::Uuid) -> Result<Option<KeyRecord>> {
        crate::db::api_keys::get(&self.pool, tenant, id).await
    }
    async fn update_key(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        editor: KeyEditor<'_>,
        patch: &KeyPatch,
        actor: &str,
    ) -> Result<UpdateOutcome> {
        let actor = audit_actor(actor);
        let outcome =
            crate::db::api_keys::update(&self.pool, tenant, id, editor, patch, &actor).await?;
        // OG-51: a key's cache narrowing rides the entitlement refresh — drop this workspace's
        // entry so the next request re-resolves inline rather than within the refresh-ahead.
        if let UpdateOutcome::Updated { changed, .. } = &outcome
            && changed.contains(&"cache")
            && let Some(cache) = &self.entitlements
        {
            cache.invalidate(*tenant.as_uuid()).await;
        }
        Ok(outcome)
    }
    async fn revoke_key(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let actor = audit_actor(actor);
        crate::db::api_keys::revoke_key(&self.pool, tenant, id, &actor).await
    }
    async fn recorded_spend(
        &self,
        tenant: &TenantId,
        key_id: uuid::Uuid,
        cadence: crate::spend::BudgetReset,
    ) -> Option<f64> {
        recorded_spend_from_clickhouse(
            self.ch_url.as_deref(),
            self.entitlements.as_ref(),
            tenant,
            key_id,
            cadence,
        )
        .await
    }
}

/// `recorded_usd` for `GET /v1/keys/{id}`: the SAME query the key budget seeds
/// from (`key_spend_sql(cadence)`), tenant-first, capped at the tenant's tier.
///
/// **Fail to `None`, never to `0`.** The budget seed fails OPEN to 0 because a
/// ClickHouse fault must not stop production traffic; a DISPLAY that turned the
/// same fault into "$0.00 spent" would tell a customer their key is idle while it
/// may be at its cap. Unknown is rendered as unknown.
async fn recorded_spend_from_clickhouse(
    ch_url: Option<&str>,
    entitlements: Option<&Arc<crate::entitlement_cache::EntitlementCache>>,
    tenant: &TenantId,
    key_id: uuid::Uuid,
    cadence: crate::spend::BudgetReset,
) -> Option<f64> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SumRow {
        usd: f64,
    }
    let url = ch_url?.to_owned();
    let tier = crate::clickhouse_query::tier_for_tenant(entitlements, tenant).await;
    let sql =
        crate::clickhouse_query::TenantQuery::new(crate::server::key_spend_sql(cadence), tier)
            .with_log_comment(format!("tenant_id={tenant}"))
            .sql_with_settings();
    match crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(tenant.to_string())
        .bind(key_id.to_string())
        .fetch_one::<SumRow>()
        .await
    {
        Ok(row) if row.usd.is_finite() && row.usd >= 0.0 => Some(row.usd),
        Ok(_) => None,
        Err(e) => {
            // Human-triggered (a drawer opening), not per-request traffic: debug,
            // and the UI states "Spend unavailable right now" from the `null`.
            tracing::debug!(error = %e, tenant_id = %tenant, "recorded_usd read failed; reporting unknown");
            None
        }
    }
}

/// Router state — the mint seam behind an `Arc` (clone-cheap per request).
#[derive(Clone)]
pub struct KeyRoutesState {
    pub minter: Arc<dyn KeyMinter>,
}

/// `POST /v1/keys` request body.
#[derive(Debug, Deserialize)]
struct CreateKeyBody {
    name: String,
    /// A13. Omitted ⇒ the full set, spelled out (see `db::api_keys::mint`).
    /// An UNRECOGNISED slug is a 400 here rather than a silent drop: at mint
    /// time the caller is a human choosing capabilities, and quietly ignoring
    /// what they asked for would hand back a key that does less than the UI just
    /// told them it does. (At AUTH time the same slug denies silently — there
    /// the caller is a machine presenting a credential, and the safe answer is
    /// simply "not granted".)
    #[serde(default)]
    scope: Option<Vec<String>>,
    /// RFC3339. Must be in the future.
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    budget_usd_monthly: Option<f64>,
    /// GWY-43. Requests-per-minute ceiling for this one key. Omitted ⇒ the key
    /// inherits the tenant's plan tier, exactly as every key did before GWY-43.
    ///
    /// Wire type is `i64`, not `u32`, ON PURPOSE: a `u32` field makes serde
    /// refuse a negative before the handler runs, and the caller gets axum's
    /// 422 deserialization text instead of the 400 naming the field that the
    /// budget next to it returns. Taking the wider type keeps ONE validator,
    /// here, for every out-of-range value.
    #[serde(default)]
    rate_limit_rpm: Option<i64>,
    /// BILL-01 A3. `"daily" | "weekly" | "monthly"`. Omitted ⇒ `"monthly"`
    /// (the column's own default, and every key minted before A3).
    #[serde(default)]
    budget_reset: Option<String>,
    /// BILL-01 A3. Opt IN to the velocity breaker for this key. Omitted ⇒
    /// `false` — a customer must ask for it.
    #[serde(default)]
    velocity_breaker: bool,
    /// OG-23: mint the key into this project (a LIVE project of this tenant). Owner only.
    #[serde(default)]
    project_id: Option<String>,
    /// OG-23: the key's environment label — one of the project's. Owner only.
    #[serde(default)]
    environment: Option<String>,
    /// OG-20: the key's own policy (`specs/OG-20-per-key-policy.md` §2). Owner only.
    #[serde(default)]
    policy: Option<serde_json::Value>,
}

/// `POST /v1/keys` response. camelCase to match the dashboard's `CreateResult`
/// (`apps/web/components/settings/ApiKeyManager.tsx`). `rawKey` is shown once.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateKeyResponse {
    /// Only on rotation: the OLD key's retirement time, not the successor's.
    #[serde(skip_serializing_if = "Option::is_none")]
    old_key_revoked_at: Option<String>,
    id: String,
    name: String,
    key_prefix: String,
    /// RFC3339 UTC. `null` on a fresh key (matches the list `lastUsedAt`).
    last_used_at: Option<String>,
    created_at: String,
    raw_key: String, // secret-field-ok: one-time reveal at mint; DB keeps only hashes (B-430)
    /// A13. `null` only for a pre-A13 key; every newly minted key is explicit.
    scope: Option<Vec<String>>,
    /// A13. RFC3339 UTC, `null` = never expires.
    expires_at: Option<String>,
    /// GWY-43. The ceilings as VALIDATED here and handed to the INSERT — echoed
    /// back so the 201 reports what the row holds rather than leaving the caller
    /// to assume its input survived. `null` = uncapped / plan default.
    budget_usd_monthly: Option<f64>,
    rate_limit_rpm: Option<i32>,
    budget_reset: &'static str,
    velocity_breaker: bool,
    /// OG-23 / OG-20, as stored.
    project_id: Option<String>,
    environment: Option<String>,
    policy: Option<serde_json::Value>,
}

/// The known scope slugs, for every 400 this route emits.
///
/// ONE source for the list so the three refusals (omitted, empty, unknown) can
/// never disagree about the vocabulary — a caller told two different sets of
/// "known scopes" by two errors on the same route learns to trust neither.
fn known_scope_slugs() -> Vec<&'static str> {
    tracelane_shared::api_scope::Scope::all()
        .iter()
        .map(|s| s.as_slug())
        .collect()
}

/// Mount the mint route. Merged in `server.rs` when Postgres is configured.
pub fn routes() -> Router<KeyRoutesState> {
    Router::new()
        .route("/v1/keys", post(create_key_handler))
        .route("/v1/keys/rotation-policy", get(rotation_policy_handler))
        .route("/v1/keys/{id}/rotate", post(rotate_key_handler))
        // SET-38 (read + edit in place) and B-586 (revoke through the gateway, so
        // the in-process auth cache is invalidated). `rotation-policy` above is a
        // static segment, which the router matches before this capture.
        .route(
            "/v1/keys/{id}",
            get(get_key_handler)
                .patch(update_key_handler)
                .delete(revoke_key_handler),
        )
}

// ── SET-38: GET / PATCH /v1/keys/{id}, and B-586: DELETE /v1/keys/{id} ──────

/// A JSON error body: a stable `error` code, a human `message`, and the `field`
/// when one field is at fault. Every SET-38 / B-586 refusal uses this shape, so
/// the dashboard can put the text beside the named field.
pub(crate) fn json_error(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
    field: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({ "error": code, "message": message.into() });
    if let Some(f) = field {
        body["field"] = serde_json::Value::String(f.to_owned());
    }
    (status, Json(body)).into_response()
}

fn field_error(e: FieldError) -> Box<Response> {
    Box::new(json_error(
        StatusCode::BAD_REQUEST,
        "invalid_field",
        e.message,
        Some(e.field),
    ))
}

/// A path id that is not a UUID names no key: the same 404 as a missing one, and
/// only AFTER authentication (axum's typed `Path<Uuid>` would 400 an anonymous
/// caller before the auth check ran).
fn parse_key_id(raw: &str) -> Result<uuid::Uuid, Box<Response>> {
    uuid::Uuid::parse_str(raw).map_err(|_| Box::new(key_not_found()))
}

fn key_not_found() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "not_found",
        "key not found, expired, or revoked",
        None,
    )
}

pub(crate) fn role_forbidden(required: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        crate::auth::role_forbidden_json(required),
    )
        .into_response()
}

/// `OG-23`: a read route refused for a credential without the `read` scope or a role.
pub(crate) fn insufficient_read() -> Response {
    json_error(
        StatusCode::FORBIDDEN,
        "insufficient_scope",
        "this credential cannot read projects — it needs a workspace role, or an API key \
         with the `read` scope",
        None,
    )
}

/// Who may EDIT a key's limits (spec §2 "authorization"). Fail CLOSED:
///
/// * a **verified owner** (WorkOS JWT, role owner/admin) — any key;
/// * a **member** (WorkOS JWT) — only a key they minted (`minted_by = sub`);
/// * the **self-host operator** (master key) — any key;
/// * **everything else is refused**: a viewer, a JWT with an absent or
///   unrecognised role (PL-9), an mTLS identity, and **any `tlane_` API key** —
///   a key must never edit keys, itself included, or a budget-capped key could
///   lift its own cap.
///
/// This is deliberately NARROWER than create's `can_mint_keys`: that lets a
/// member act on the workspace in general, and applied to editing it would let a
/// member throttle an owner's production key to 1 req/min — the same ingress
/// kill the web revoke route refuses.
///
/// OG-34: read from the matrix — `ManageAllKeys` edits any key, `MintKeys` only the
/// caller's own (`auth/capability.rs`). Neither is held by an API key or mTLS.
fn key_editor(claims: &crate::auth::Claims) -> Option<KeyEditor<'_>> {
    use crate::auth::capability::Capability;
    if claims.can(Capability::ManageAllKeys) {
        Some(KeyEditor::Any)
    } else if claims.can(Capability::MintKeys) {
        Some(KeyEditor::MintedBy(&claims.sub))
    } else {
        None
    }
}

/// Who may READ one key: any recognised workspace role on a human session (the
/// dashboard's key list is visible to every role), or the self-host operator.
/// Not an API key — a machine credential has no business enumerating keys.
/// OG-34: the matrix's `ViewKeys` row.
fn can_read_keys(claims: &crate::auth::Claims) -> bool {
    claims.can(crate::auth::capability::Capability::ViewKeys)
}

/// H1: who may GRANT `passthrough` — a verified owner (JWT `owner`/`admin`), or the
/// single-tenant self-host master key, which IS the operator of that deployment and has
/// no role system (`Claims::can_admin`'s `has_no_role_system` arm). A tenant `tlane_` key
/// is neither (PL-9b), so a member-minted key still cannot self-grant.
///
/// **The second arm is UNREACHABLE today** (re-review L-3, settled 2026-10-03): these
/// routes mount only with a Postgres pool (`server.rs`, `if let Some(pool) = state.pg`)
/// and self-host refuses to boot with one (`tracelane_shared::self_host::from_env`). The
/// master key itself is `LegacyFullSurface`, which withholds `passthrough`
/// (`api_scope.rs`), so passthrough does not exist on self-host at all. The arm is kept
/// so the operator is the owner if self-host ever gains a control plane.
/// OG-34: the matrix's `GrantPassthrough` row.
///
/// rev5 H1 — **a key never holds more than its minter's role allows.** The refusal for a
/// (validated, canonical) scope list the caller may not put on a key, or `None`. Every
/// scope is judged by the capability that grants it (`capability::scope_grant_capability`):
/// `passthrough` needs `grant_passthrough` (the 2026-10-02 H1), `admin` needs
/// `grant_admin_scope` — an `admin` key holds the matrix's `api_key` column
/// (`edit_budgets`, `write_prompts`), which a developer does not, so a developer minting
/// one (or adding it to their own key) was a privilege escalation. Checked on mint and
/// PATCH, before the store, so a refusal creates and changes nothing. An unknown slug
/// never reaches here (`validate_scope` refuses it).
fn scope_refusal(claims: &crate::auth::Claims, scope: &[String]) -> Option<Response> {
    let refused = scope
        .iter()
        .filter_map(|s| tracelane_shared::api_scope::Scope::from_slug(s))
        .any(|s| !claims.can(crate::auth::capability::scope_grant_capability(s)));
    refused.then(|| role_forbidden("owner"))
}

/// Who may REVOKE: a verified owner (as the web revoke's `requireOrgAdmin`, and as
/// rotate) or the self-host operator. Never a member, never a key.
/// OG-34: the matrix's `ManageAllKeys` row.
fn can_revoke_keys(claims: &crate::auth::Claims) -> bool {
    claims.can(crate::auth::capability::Capability::ManageAllKeys)
}

/// A key as the settings surface sees it: the create response without `rawKey`,
/// plus who minted it and its scheduled retirement. camelCase, like the create
/// response and the dashboard's `ApiKeyRow`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyView {
    id: String,
    name: String,
    key_prefix: String,
    last_used_at: Option<String>,
    created_at: String,
    minted_by: Option<String>,
    scope: Option<Vec<String>>,
    expires_at: Option<String>,
    budget_usd_monthly: Option<f64>,
    rate_limit_rpm: Option<i32>,
    budget_reset: &'static str,
    velocity_breaker: bool,
    /// A future value: the key is retiring (rotated, in its grace window).
    revoked_at: Option<String>,
    /// OG-23: the key's project and environment label.
    project_id: Option<String>,
    environment: Option<String>,
    /// OG-20: the key's own policy (its project's is on `GET /v1/projects/{id}`).
    policy: Option<serde_json::Value>,
    /// OG-51: the key's own cache narrowing, if any.
    cache: Option<serde_json::Value>,
}

impl From<KeyRecord> for KeyView {
    fn from(r: KeyRecord) -> Self {
        Self {
            id: r.id.to_string(),
            name: r.name,
            key_prefix: r.key_prefix,
            last_used_at: r.last_used_at.map(|t| t.to_rfc3339()),
            created_at: r.created_at.to_rfc3339(),
            minted_by: r.minted_by,
            scope: r.scope,
            expires_at: r.expires_at.map(|t| t.to_rfc3339()),
            budget_usd_monthly: r.budget_usd_monthly,
            rate_limit_rpm: r.rate_limit_rpm,
            budget_reset: r.budget_reset.as_str(),
            velocity_breaker: r.velocity_breaker,
            revoked_at: r.revoked_at.map(|t| t.to_rfc3339()),
            project_id: r.project_id.map(|p| p.to_string()),
            environment: r.environment,
            policy: r.policy,
            cache: r.cache,
        }
    }
}

/// `spend` in `GET /v1/keys/{id}` — spec §2, field names as the spec writes them.
#[derive(Debug, Serialize)]
struct KeySpendView {
    /// `"day" | "week" | "month"` — the key's `budget_reset` window.
    window: &'static str,
    /// RFC3339 UTC start of the current window (the same UTC boundary the
    /// ClickHouse query's `toStartOfDay` / `toMonday` / `toStartOfMonth` reads).
    window_starts_at: String,
    /// `null` = could not be read. A true zero is `0.0`.
    recorded_usd: Option<f64>,
}

#[derive(Debug, Serialize)]
struct KeyDetailResponse {
    #[serde(flatten)]
    key: KeyView,
    spend: KeySpendView,
}

#[derive(Debug, Serialize)]
struct KeyUpdateResponse {
    #[serde(flatten)]
    key: KeyView,
    /// Wire names of the fields that actually changed; `[]` for a no-op.
    changed: Vec<&'static str>,
}

/// The UTC start of the budget window `cadence` is in at `now`.
fn window_start(
    cadence: crate::spend::BudgetReset,
    now: chrono::DateTime<chrono::Utc>,
) -> (&'static str, chrono::DateTime<chrono::Utc>) {
    use chrono::{Datelike as _, TimeZone as _};
    let day = now.date_naive();
    let (label, date) = match cadence {
        crate::spend::BudgetReset::Daily => ("day", day),
        crate::spend::BudgetReset::Weekly => (
            "week",
            day - chrono::Duration::days(i64::from(day.weekday().num_days_from_monday())),
        ),
        crate::spend::BudgetReset::Monthly => ("month", day.with_day(1).unwrap_or(day)),
    };
    (
        label,
        chrono::Utc.from_utc_datetime(&date.and_time(chrono::NaiveTime::MIN)),
    )
}

/// `GET /v1/keys/{id}` — one key plus its recorded spend this budget window.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn get_key_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let claims = match claims_from_auth(&headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !can_read_keys(&claims) {
        return role_forbidden("viewer");
    }
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let id = match parse_key_id(&id) {
        Ok(id) => id,
        Err(r) => return *r,
    };
    let record = match state.minter.get_key(&claims.tenant_id, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return key_not_found(),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "API key read failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to read API key",
                None,
            );
        }
    };
    let (window, starts) = window_start(record.budget_reset, chrono::Utc::now());
    let recorded_usd = state
        .minter
        .recorded_spend(&claims.tenant_id, record.id, record.budget_reset)
        .await;
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(KeyDetailResponse {
            key: record.into(),
            spend: KeySpendView {
                window,
                window_starts_at: starts.to_rfc3339(),
                recorded_usd,
            },
        }),
    )
        .into_response()
}

/// Present-and-null vs absent — the JSON Merge Patch distinction. With
/// `#[serde(default)]`, an absent field stays `None`; a present one (including
/// `null`) becomes `Some(..)`.
pub(crate) fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// `PATCH /v1/keys/{id}` body — RFC 7396. Absent = unchanged, `null` = clear,
/// value = set. `deny_unknown_fields`: a `tenant_id` (or any other smuggled
/// field) is a 400, never silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchKeyBody {
    #[serde(default, deserialize_with = "present")]
    name: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    scope: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "present")]
    expires_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    budget_usd_monthly: Option<Option<f64>>,
    /// `i64` for the same reason as create: one validator reports every
    /// out-of-range value as a 400 naming the field.
    #[serde(default, deserialize_with = "present")]
    rate_limit_rpm: Option<Option<i64>>,
    #[serde(default, deserialize_with = "present")]
    budget_reset: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    velocity_breaker: Option<Option<bool>>,
    /// OG-23: `null` takes the key out of its project.
    #[serde(default, deserialize_with = "present")]
    project_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    environment: Option<Option<String>>,
    /// OG-20: `null` clears the key's own policy (its project's still applies).
    #[serde(default, deserialize_with = "present")]
    policy: Option<Option<serde_json::Value>>,
    /// OG-51: the key's own cache narrowing — `{"mode":"off"?,"namespace_by"?}`; `null`
    /// clears it (which widens: owner only).
    #[serde(default, deserialize_with = "present")]
    cache: Option<Option<serde_json::Value>>,
}

fn cannot_clear(field: &'static str) -> Box<Response> {
    Box::new(json_error(
        StatusCode::BAD_REQUEST,
        "invalid_field",
        format!("{field} cannot be cleared — send a value, or omit it to leave it unchanged"),
        Some(field),
    ))
}

/// Validate a patch through the SAME validators create uses. Pure (the clock is a
/// parameter), so every refusal is unit-testable.
fn validate_patch(
    body: PatchKeyBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<KeyPatch, Box<Response>> {
    let mut patch = KeyPatch::default();
    match body.name {
        None => {}
        Some(None) => return Err(cannot_clear("name")),
        Some(Some(n)) => patch.name = Some(validate_name(&n).map_err(field_error)?.to_owned()),
    }
    match body.scope {
        None => {}
        // A key may LEAVE the legacy full-surface state and never re-enter it:
        // `null` would widen the key to every scope, `admin` included.
        Some(None) => {
            return Err(Box::new(json_error(
                StatusCode::BAD_REQUEST,
                "scope_cannot_become_legacy",
                "scope cannot be set to null — a key can leave the legacy full-access state \
                 but never re-enter it. Send the scopes this key needs.",
                Some("scope"),
            )));
        }
        Some(Some(v)) => patch.scope = Some(validate_scope(Some(v)).map_err(field_error)?),
    }
    match body.expires_at {
        None => {}
        Some(None) => patch.expires_at = Some(None),
        Some(Some(raw)) => {
            let at = validate_expires_at(&raw, now).map_err(|mut e| {
                if e.message.ends_with("in the future") {
                    e.message.push_str(" — to stop a key now, revoke it");
                }
                field_error(e)
            })?;
            patch.expires_at = Some(Some(at));
        }
    }
    match body.budget_usd_monthly {
        None => {}
        Some(None) => patch.budget_usd_monthly = Some(None),
        Some(Some(b)) => {
            patch.budget_usd_monthly = Some(Some(validate_budget_usd(b).map_err(field_error)?));
        }
    }
    match body.rate_limit_rpm {
        None => {}
        Some(None) => patch.rate_limit_rpm = Some(None),
        Some(Some(r)) => {
            patch.rate_limit_rpm = Some(Some(validate_rate_limit_rpm(r).map_err(field_error)?));
        }
    }
    match body.budget_reset {
        None => {}
        Some(None) => return Err(cannot_clear("budget_reset")),
        Some(Some(r)) => {
            patch.budget_reset = Some(validate_budget_reset(&r).map_err(field_error)?);
        }
    }
    match body.velocity_breaker {
        None => {}
        Some(None) => return Err(cannot_clear("velocity_breaker")),
        Some(Some(v)) => patch.velocity_breaker = Some(v),
    }
    match body.project_id {
        None => {}
        Some(None) => patch.project_id = Some(None),
        Some(Some(raw)) => {
            patch.project_id = Some(Some(validate_project_id(&raw).map_err(field_error)?));
        }
    }
    match body.environment {
        None => {}
        Some(None) => patch.environment = Some(None),
        Some(Some(raw)) => {
            patch.environment = Some(Some(validate_environment(&raw).map_err(field_error)?));
        }
    }
    match body.policy {
        None => {}
        Some(None) => patch.policy = Some(None),
        Some(Some(v)) => {
            patch.policy = Some(Some(
                crate::project_routes::validate_policy(&v).map_err(|e| Box::new(e.response()))?,
            ));
        }
    }
    match body.cache {
        None => {}
        Some(None) => patch.cache = Some(None),
        Some(Some(v)) => {
            let k = crate::db::cache_settings::KeyCache::parse_strict(&v).map_err(
                |(field, message)| {
                    Box::new(json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_field",
                        message,
                        Some(field.as_str()),
                    ))
                },
            )?;
            patch.cache = Some(Some(k.to_json()));
        }
    }
    if patch == KeyPatch::default() {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "nothing_to_change",
            "the patch names no field — send at least one of name, scope, expires_at, \
             budget_usd_monthly, rate_limit_rpm, budget_reset, velocity_breaker, project_id, \
             environment, policy, cache",
            None,
        )));
    }
    Ok(patch)
}

/// OG-23: a project id in a body — a UUID (anything else names no project: the same
/// 404 an absent or foreign one gets, decided by the store).
fn validate_project_id(raw: &str) -> Result<uuid::Uuid, FieldError> {
    uuid::Uuid::parse_str(raw.trim())
        .map_err(|_| FieldError::new("project_id", "project_id must be a project's id (a UUID)"))
}

/// OG-23: an environment label — the migration's slug CHECK, said as a 400.
fn validate_environment(raw: &str) -> Result<String, FieldError> {
    let e = raw.trim();
    if crate::project_routes::valid_environment(e) {
        Ok(e.to_owned())
    } else {
        Err(FieldError::new(
            "environment",
            "environment must be lower-case letters, digits, `_` and `-`, starting with a \
             letter or digit, at most 32",
        ))
    }
}

/// OG-20 / OG-23: does this patch touch the key's governance (project, environment or
/// policy)? Those are owner decisions — a member must not lift a restriction an owner
/// put on a key, even one they minted.
fn touches_governance(patch: &KeyPatch) -> bool {
    patch.project_id.is_some()
        || patch.environment.is_some()
        || patch.policy.is_some()
        // OG-51: removing a cache narrowing WIDENS the cache, so a key's cache document is an
        // owner decision like its policy — a member must not undo what an owner set.
        || patch.cache.is_some()
}

/// `PATCH /v1/keys/{id}` — edit a key's limits in place (SET-38). Order: auth →
/// role → body → the transaction (which authorizes a member against
/// `minted_by` under the row lock). Tenant ONLY from the validated claims.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn update_key_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let claims = match claims_from_auth(&headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let Some(editor) = key_editor(&claims) else {
        return role_forbidden("member");
    };
    // OG-36: allowlist + SSO-required; the actor is the OG-35 audit row's.
    let control = match crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::MintKeys,
        &headers,
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let id = match parse_key_id(&id) {
        Ok(id) => id,
        Err(r) => return *r,
    };
    // An OBJECT, checked before the typed parse: serde also builds a struct from
    // a JSON ARRAY, positionally — `["x"]` would read as `{"name":"x"}`. Found by
    // this route's own refusal test; a patch must name every field it sets.
    let parsed: PatchKeyBody =
        match serde_json::from_slice::<serde_json::Value>(&body).and_then(|v| {
            if v.is_object() {
                serde_json::from_value(v)
            } else {
                Err(serde::de::Error::custom("expected a JSON object"))
            }
        }) {
            Ok(b) => b,
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_body",
                    format!("the body must be a JSON object of the editable fields: {e}"),
                    None,
                );
            }
        };
    let patch = match validate_patch(parsed, chrono::Utc::now()) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    // H1 (security review 2026-10-02): `passthrough` forwards raw, unscanned bodies to a
    // provider, so only a verified owner may put it in a key's scope set — never a member,
    // even on a key they minted. Checked before the store, so a refusal changes nothing.
    // Fail-CLOSED: any scope edit naming `passthrough` needs the owner, whether or not the
    // key already had it.
    if let Some(refused) = patch.scope.as_ref().and_then(|s| scope_refusal(&claims, s)) {
        return refused;
    }
    // OG-20 / OG-23: a key's project, environment and policy are owner decisions.
    if touches_governance(&patch) && !crate::project_routes::may_manage_governance(&claims) {
        return role_forbidden("owner");
    }
    match crate::db::control_audit::scoped(
        control.audit.clone(),
        state
            .minter
            .update_key(&claims.tenant_id, id, editor, &patch, &claims.sub),
    )
    .await
    {
        Ok(UpdateOutcome::Updated { record, changed }) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(KeyUpdateResponse {
                key: (*record).into(),
                changed,
            }),
        )
            .into_response(),
        Ok(UpdateOutcome::NotFound) => key_not_found(),
        // A member on a key someone else minted: only an owner may.
        Ok(UpdateOutcome::Forbidden) => role_forbidden("owner"),
        Ok(UpdateOutcome::ProjectNotFound) => project_not_found(),
        Ok(UpdateOutcome::EnvironmentNotInProject { environment }) => {
            environment_not_in_project(&environment)
        }
        Ok(UpdateOutcome::EnvironmentNeedsProject) => environment_needs_project(),
        Ok(UpdateOutcome::Retiring { revoked_at }) => {
            let mut resp = json_error(
                StatusCode::CONFLICT,
                "key_retiring",
                format!(
                    "This key is being rotated and retires {}. Edit its successor instead.",
                    revoked_at.to_rfc3339()
                ),
                None,
            );
            resp.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            resp
        }
        Err(err) => {
            // Fail CLOSED: the transaction rolled back, so "nothing was changed"
            // is true, and the message says so.
            tracing::error!(error = %format!("{err:#}"), "API key update failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "not_saved",
                "failed to update API key — nothing was changed",
                None,
            )
        }
    }
}

fn project_not_found() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "project_not_found",
        "project not found",
        Some("project_id"),
    )
}

fn environment_not_in_project(environment: &str) -> Response {
    json_error(
        StatusCode::CONFLICT,
        "environment_not_in_project",
        format!(
            "`{environment}` is not one of the project's environments — add it to the project \
             first, or choose one of its environments"
        ),
        Some("environment"),
    )
}

fn environment_needs_project() -> Response {
    json_error(
        StatusCode::BAD_REQUEST,
        "invalid_field",
        "an environment label needs a project — set project_id too",
        Some("environment"),
    )
}

/// `DELETE /v1/keys/{id}` — B-586: revoke through the gateway so the in-process
/// auth cache is invalidated in the same step. 204 on success; 404 when the key
/// is not in this tenant or already revoked.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn revoke_key_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let claims = match claims_from_auth(&headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !can_revoke_keys(&claims) {
        return role_forbidden("owner");
    }
    // OG-36: allowlist + SSO-required; the actor is the OG-35 audit row's. rev6 N1:
    // revoking a key is an incident control — its own per-principal bucket.
    let control = match crate::control_plane::require_control(
        &claims,
        crate::control_plane::incident(crate::auth::capability::Capability::ManageAllKeys),
        &headers,
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let id = match parse_key_id(&id) {
        Ok(id) => id,
        Err(r) => return *r,
    };
    match crate::db::control_audit::scoped(
        control.audit.clone(),
        state.minter.revoke_key(&claims.tenant_id, id, &claims.sub),
    )
    .await
    {
        Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "key not found or already revoked",
            None,
        ),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "API key revoke failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "not_revoked",
                "failed to revoke API key — the key is unchanged",
                None,
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateKeyBody {
    grace_hours: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationPolicyResponse {
    grace_hours: i64,
}

/// Off-hot-path reference read. Fail CLOSED rather than invent a default.
#[tracing::instrument(skip(state, headers))]
async fn rotation_policy_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
) -> Result<Json<RotationPolicyResponse>, (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    if !claims.can_mint_keys() {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("member"),
        ));
    }
    let grace_hours = state.minter.rotation_grace_hours().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "rotation policy unavailable".into(),
        )
    })?;
    Ok(Json(RotationPolicyResponse { grace_hours }))
}

/// Rotate credentials only for a verified workspace owner; fail CLOSED.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn rotate_key_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<RotateKeyBody>,
) -> Result<Response, (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    if !claims.is_verified_owner() {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        ));
    }
    // OG-36: allowlist + SSO-required; the actor is the OG-35 audit row's.
    let control = crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::ManageAllKeys,
        &headers,
    )
    .await
    .map_err(crate::control_plane::ControlRefusal::into_pair)?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let grace = match body.grace_hours {
        Some(hours) => hours,
        None => state.minter.rotation_grace_hours().await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "rotation policy unavailable".into(),
            )
        })?,
    };
    if !crate::db::api_keys::valid_rotation_grace(grace) {
        return Err((
            StatusCode::BAD_REQUEST,
            "grace_hours must be a non-negative whole number within the timestamp range".into(),
        ));
    }
    let result = crate::db::control_audit::scoped(
        control.audit.clone(),
        state
            .minter
            .rotate(&claims.tenant_id, id, &claims.sub, grace),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to rotate API key".into(),
        )
    })?
    .ok_or((
        StatusCode::NOT_FOUND,
        "key not found, expired, or already rotated/revoked".into(),
    ))?;
    let minted = result.minted;
    Ok((
        StatusCode::CREATED,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(CreateKeyResponse {
            old_key_revoked_at: Some(result.revoked_at.to_rfc3339()),
            id: minted.api_key.id.to_string(),
            name: minted.api_key.name,
            key_prefix: minted.key_prefix,
            last_used_at: None,
            created_at: minted.api_key.created_at.to_rfc3339(),
            raw_key: minted.raw_key,
            scope: minted.api_key.scope,
            expires_at: minted.api_key.expires_at.map(|v| v.to_rfc3339()),
            budget_usd_monthly: result.options.budget_usd_monthly,
            rate_limit_rpm: result.options.rate_limit_rpm,
            budget_reset: result
                .options
                .budget_reset
                .unwrap_or(crate::spend::BudgetReset::Monthly)
                .as_str(),
            velocity_breaker: result.options.velocity_breaker,
            project_id: result.options.project_id.map(|p| p.to_string()),
            environment: result.options.environment,
            policy: result.options.policy,
        }),
    )
        .into_response())
}

// ── SET-38 B1: ONE validator per field, shared by create and edit ───────────

/// One refused field: its wire name and the 400 text that names the problem.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldError {
    field: &'static str,
    message: String,
}

impl FieldError {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

/// `POST /v1/keys`'s refusal shape: a plain-text 400 carrying the message.
fn bad_request(e: FieldError) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.message)
}

/// Trimmed, non-empty, at most [`MAX_KEY_NAME_LEN`] characters.
fn validate_name(raw: &str) -> Result<&str, FieldError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(FieldError::new("name", "name must not be empty"));
    }
    if name.chars().count() > MAX_KEY_NAME_LEN {
        return Err(FieldError::new(
            "name",
            format!("name must be at most {MAX_KEY_NAME_LEN} characters"),
        ));
    }
    Ok(name)
}

/// A13 / R73 — a key must state what it may do: required, non-empty, every slug
/// known. Normalised and de-duplicated so the stored array is canonical.
fn validate_scope(raw: Option<Vec<String>>) -> Result<Vec<String>, FieldError> {
    let raw = match raw {
        // R73 (founder ruling, 2026-08-22) — **AN OMITTED `scope` IS A 400.**
        //
        // This arm used to be `None => None`, with `.with_default_scope()` below
        // filling in `{chat, read, ingest}`. Migration 0024's hand-off note always
        // said the mint route must REQUIRE a scope; the deviation was taken on the
        // stated grounds that requiring one "would 400 every existing caller of
        // `POST /v1/keys` the moment this deploys, the dashboard proxy included."
        //
        // THAT REASON WAS MEASURED AND IS FALSE. Of 37 keys ever minted on prod,
        // 23 carry SQL NULL and 14 an explicit scope — and all 14 explicit ones are
        // revoked, so **zero live keys were minted through this default**. The
        // dashboard cannot reach the arm either: `ApiKeyManager.tsx` gates submit on
        // `scope.length > 0`, and the proxy forwards the field only when present.
        // Self-host cannot reach it at all — minting needs a Postgres control plane
        // that self-host does not run (`README.md:71`).
        //
        // Why REQUIRED beats a narrower default: a default is a decision made by
        // whoever wrote it, for every caller who never reads it. `chat` spends the
        // tenant's provider money, so the quiet path was handing out the one
        // capability with a bill attached. Refusing makes the caller state it.
        None => {
            return Err(FieldError::new(
                "scope",
                format!(
                    "scope is required — a key must state what it may do, because \
                     an omitted scope used to grant `chat`, which spends this \
                     workspace's provider budget. Pass e.g. \"scope\": [\"chat\", \
                     \"read\"]. Known scopes: {}",
                    known_scope_slugs().join(", ")
                ),
            ));
        }
        Some(raw) => raw,
    };
    if raw.is_empty() {
        return Err(FieldError::new(
            "scope",
            format!(
                "scope must not be empty — state at least one. Known scopes: {}",
                known_scope_slugs().join(", ")
            ),
        ));
    }
    let mut out = Vec::with_capacity(raw.len());
    for slug in &raw {
        let Some(parsed) = tracelane_shared::api_scope::Scope::from_slug(slug) else {
            return Err(FieldError::new(
                "scope",
                format!(
                    "unknown scope {slug:?} — known scopes: {}",
                    known_scope_slugs().join(", ")
                ),
            ));
        };
        // Normalise + de-duplicate so the stored array is canonical.
        let slug = parsed.as_slug().to_string();
        if !out.contains(&slug) {
            out.push(slug);
        }
    }
    Ok(out)
}

/// RFC3339, strictly after `now`. An already-expired key would authenticate
/// nothing — almost certainly a mistake, and silently writing a dead credential
/// is worse than refusing.
fn validate_expires_at(
    raw: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>, FieldError> {
    let parsed = chrono::DateTime::parse_from_rfc3339(raw)
        .map_err(|e| FieldError::new("expires_at", format!("expires_at must be RFC3339: {e}")))?
        .with_timezone(&chrono::Utc);
    if parsed <= now {
        return Err(FieldError::new(
            "expires_at",
            "expires_at must be in the future",
        ));
    }
    Ok(parsed)
}

/// Finite and non-negative (`api_keys_budget_nonneg_chk` says the same at the DB).
fn validate_budget_usd(b: f64) -> Result<f64, FieldError> {
    if !b.is_finite() || b < 0.0 {
        return Err(FieldError::new(
            "budget_usd_monthly",
            "budget_usd_monthly must be a finite, non-negative number",
        ));
    }
    Ok(b)
}

/// GWY-43 — same shape as the budget check, one difference: 0 is REFUSED rather
/// than accepted. A zero budget is a coherent (if useless) ceiling, but a zero
/// rate limit is a key that can never be used, and `revoked_at` is how a key is
/// switched off. `api_keys_rate_limit_rpm_positive_chk` (migration 0029) says the
/// same thing at the DB; catching it here turns a constraint-violation 500 into a
/// 400 that names the field. The ceiling is `i32::MAX` because the column is
/// `integer`.
fn validate_rate_limit_rpm(rpm: i64) -> Result<i32, FieldError> {
    match i32::try_from(rpm) {
        Ok(v) if v > 0 => Ok(v),
        _ => Err(FieldError::new(
            "rate_limit_rpm",
            format!(
                "rate_limit_rpm must be a whole number of requests per minute \
                 between 1 and {} — omit it to use the workspace plan limit",
                i32::MAX
            ),
        )),
    }
}

/// BILL-01 A3 — one of the three values the `CHECK`-constrained column holds.
fn validate_budget_reset(raw: &str) -> Result<crate::spend::BudgetReset, FieldError> {
    match raw {
        "daily" => Ok(crate::spend::BudgetReset::Daily),
        "weekly" => Ok(crate::spend::BudgetReset::Weekly),
        "monthly" => Ok(crate::spend::BudgetReset::Monthly),
        other => Err(FieldError::new(
            "budget_reset",
            format!("budget_reset must be one of daily, weekly, monthly (got {other:?})"),
        )),
    }
}

/// Extract the validated claims from the `Authorization` header. Tenant
/// identity + role are sourced ONLY from a verified JWT / API key — never a
/// body or custom header (CLAUDE.md tenant-isolation invariant).
async fn claims_from_auth(
    headers: &HeaderMap,
) -> Result<crate::auth::Claims, (StatusCode, String)> {
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
    crate::auth::validate_authorization(header_str)
        .await
        .map_err(|e| (crate::auth::failure_status(&e), format!("auth failed: {e}")))
}

/// POST /v1/keys — mint an API key for the authenticated tenant.
///
/// 201 with `{id,name,keyPrefix,createdAt,lastUsedAt,rawKey}` on success; 401 if
/// unauthenticated; 400 on an empty/oversized name; 500 if minting fails. The
/// raw key is in the body once and is never logged.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn create_key_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyBody>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    // IDENTITY_TEAM_SPEC §1: viewers cannot mint keys. Members + owners may
    // (API-key / dev auth is grandfathered). Gateway is the authoritative gate.
    if !claims.can_mint_keys() {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("member"),
        ));
    }
    // OG-36: allowlist + SSO-required; the actor is the OG-35 audit row's.
    let control = crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::MintKeys,
        &headers,
    )
    .await
    .map_err(crate::control_plane::ControlRefusal::into_pair)?;
    let tenant = claims.tenant_id.clone();
    tracing::Span::current().record("tenant_id", tenant.to_string());

    // ── A13: validate every field BEFORE minting ────────────────────────────
    // Rejected here rather than at the DB so the caller gets a 400 naming the
    // problem instead of a 500 from a constraint violation. SET-38 B1: each field
    // goes through ONE shared validator, which `PATCH /v1/keys/{id}` calls too, so
    // create and edit cannot disagree about what a valid value is.
    let name = validate_name(&body.name).map_err(bad_request)?;
    let scope = validate_scope(body.scope).map_err(bad_request)?;
    // H1 (security review 2026-10-02): minting a `passthrough` key is an owner decision —
    // the scope sends raw, unscanned bodies upstream. Before minting, so nothing exists.
    if scope_refusal(&claims, &scope).is_some() {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        ));
    }
    let scope = Some(scope);
    let expires_at = body
        .expires_at
        .as_deref()
        .map(|raw| validate_expires_at(raw, chrono::Utc::now()))
        .transpose()
        .map_err(bad_request)?;
    if let Some(b) = body.budget_usd_monthly {
        validate_budget_usd(b).map_err(bad_request)?;
    }
    let rate_limit_rpm = body
        .rate_limit_rpm
        .map(validate_rate_limit_rpm)
        .transpose()
        .map_err(bad_request)?;
    let budget_reset = body
        .budget_reset
        .as_deref()
        .map(validate_budget_reset)
        .transpose()
        .map_err(bad_request)?;

    // OG-20 / OG-23: a project, an environment or a policy at mint is an owner
    // decision (as on edit). Validated before minting, so a refusal creates nothing.
    let project_id = body
        .project_id
        .as_deref()
        .map(validate_project_id)
        .transpose()
        .map_err(bad_request)?;
    let environment = body
        .environment
        .as_deref()
        .map(validate_environment)
        .transpose()
        .map_err(bad_request)?;
    let policy = match &body.policy {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(crate::project_routes::validate_policy(v).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("{}: {}", e.field, e.message),
            )
        })?),
    };
    if (project_id.is_some() || environment.is_some() || policy.is_some())
        && !crate::project_routes::may_manage_governance(&claims)
    {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        ));
    }
    let opts = crate::db::api_keys::MintOptions {
        scope,
        expires_at,
        budget_usd_monthly: body.budget_usd_monthly,
        rate_limit_rpm,
        budget_reset,
        velocity_breaker: body.velocity_breaker,
        project_id,
        environment: environment.clone(),
        policy: policy.clone(),
    };

    // Record the minting user (WorkOS `sub`) so §3 member-removal can revoke
    // exactly this user's keys. API-key / dev auth has an `apikey:`/`dev-stub`
    // sub — harmless to store; it just won't match a WorkOS user_id on removal.
    let minted_by = claims.sub.clone();
    let minted = crate::db::control_audit::scoped(
        control.audit.clone(),
        state.minter.mint(&tenant, name, Some(&minted_by), opts),
    )
    .await
    .map_err(|err| {
        // OG-23: an assignment the store refused is the caller's to fix, not a 500.
        if let Some(a) = err.downcast_ref::<crate::db::api_keys::AssignmentError>() {
            use crate::db::api_keys::AssignmentError as A;
            return match a {
                A::ProjectNotFound => (StatusCode::NOT_FOUND, "project not found".into()),
                A::EnvironmentNotInProject(e) => (
                    StatusCode::CONFLICT,
                    format!("`{e}` is not one of the project's environments"),
                ),
                A::EnvironmentNeedsProject => (
                    StatusCode::BAD_REQUEST,
                    "an environment label needs a project — set project_id too".into(),
                ),
            };
        }
        // The error chain can reference internal state (pool, pepper); log it,
        // return a terse message. Never surface the raw key or key material.
        //
        // `{err:#}` — the ALTERNATE form — not `%err`. anyhow's plain Display
        // prints ONLY the outermost `.context()` string, so this line logged
        // `INSERT INTO api_keys failed` and discarded the cause. On 2026-08-14
        // that cause was `error serializing parameter 8` and recovering it
        // took four independent probes (schema replay, prepared-statement type
        // inspection, a scratch-table trigger falsification, and a standalone
        // tokio-postgres binding probe) against one line of output. `{:#}`
        // walks the chain and would have printed it first time.
        tracing::error!(error = %format!("{err:#}"), "API key mint failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create API key".into(),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            old_key_revoked_at: None,
            id: minted.api_key.id.to_string(),
            name: minted.api_key.name,
            key_prefix: minted.key_prefix,
            last_used_at: None,
            created_at: minted.api_key.created_at.to_rfc3339(),
            raw_key: minted.raw_key,
            scope: minted.api_key.scope,
            expires_at: minted.api_key.expires_at.map(|t| t.to_rfc3339()),
            budget_usd_monthly: body.budget_usd_monthly,
            rate_limit_rpm,
            budget_reset: budget_reset
                .unwrap_or(crate::spend::BudgetReset::Monthly)
                .as_str(),
            velocity_breaker: body.velocity_breaker,
            project_id: project_id.map(|p| p.to_string()),
            environment,
            policy,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::api_keys::ApiKey;
    use chrono::{DateTime, Utc};
    use std::sync::Mutex;
    use uuid::Uuid;

    const DEV_TENANT: &str = "00000000-0000-0000-0000-000000000001";

    #[tokio::test]
    async fn rotation_route_requires_authentication() {
        use tower::ServiceExt;
        let (state, _) = mock_state();
        let response = routes()
            .with_state(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/keys/00000000-0000-0000-0000-000000000001/rotate")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rotation_returns_one_time_successor_and_preserves_settings() {
        let _guard = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let response = rotate_key_handler(
            State(state),
            bearer_headers(),
            Path(Uuid::nil()),
            Json(RotateKeyBody { grace_hours: None }),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(out["scope"], serde_json::json!(["read"]));
        assert_eq!(out["budgetUsdMonthly"], 12.0);
        assert!(out["rawKey"].as_str().unwrap().starts_with("tlane_"));
        assert!(out["oldKeyRevokedAt"].is_string());
        assert_eq!(seen.lock().unwrap().as_slice(), &[DEV_TENANT]);
    }

    #[tokio::test]
    async fn rotation_refuses_negative_grace_before_minting() {
        let _guard = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let error = rotate_key_handler(
            State(state),
            bearer_headers(),
            Path(Uuid::nil()),
            Json(RotateKeyBody {
                grace_hours: Some(-1),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(seen.lock().unwrap().is_empty());
    }

    /// Records the tenant it was asked to mint for so tests can prove the
    /// handler passes `Claims.tenant_id` (never a body/header value).
    struct MockKeyMinter {
        seen: Arc<Mutex<Vec<String>>>,
        /// A13: what the handler actually passed down, so a test can assert the
        /// VALIDATED+NORMALISED scope rather than just that minting happened.
        last_opts: Arc<Mutex<Option<crate::db::api_keys::MintOptions>>>,
    }
    #[async_trait::async_trait]
    impl KeyMinter for MockKeyMinter {
        async fn rotation_grace_hours(&self) -> Result<i64> {
            Ok(24)
        }
        async fn rotate(
            &self,
            tenant: &TenantId,
            _id: uuid::Uuid,
            actor: &str,
            grace_hours: i64,
        ) -> Result<Option<crate::db::api_keys::RotatedKey>> {
            let options = crate::db::api_keys::MintOptions {
                scope: Some(vec!["read".into()]),
                budget_usd_monthly: Some(12.0),
                ..Default::default()
            };
            let minted = self
                .mint(tenant, "rotated", Some(actor), options.clone())
                .await?;
            Ok(Some(crate::db::api_keys::RotatedKey {
                minted,
                options,
                revoked_at: Utc::now() + chrono::Duration::hours(grace_hours),
            }))
        }
        async fn mint(
            &self,
            tenant: &TenantId,
            name: &str,
            _minted_by: Option<&str>,
            opts: crate::db::api_keys::MintOptions,
        ) -> Result<MintedKey> {
            self.seen.lock().unwrap().push(tenant.to_string());
            let scope = opts.scope.clone();
            let expires_at = opts.expires_at;
            *self.last_opts.lock().unwrap() = Some(opts);
            Ok(MintedKey {
                api_key: ApiKey {
                    id: Uuid::nil(),
                    name: name.to_string(),
                    created_at: DateTime::<Utc>::from_timestamp(1_778_000_000, 0).unwrap(),
                    scope,
                    expires_at,
                },
                key_prefix: "AbC012".into(),
                raw_key: "tlane_MOCKKEYBODYdonotuseinprod".into(),
            })
        }
        // The mint/rotate tests never reach these; SET-38's own mock is below.
        async fn get_key(&self, _: &TenantId, _: Uuid) -> Result<Option<KeyRecord>> {
            anyhow::bail!("not used by the mint tests")
        }
        async fn update_key(
            &self,
            _: &TenantId,
            _: Uuid,
            _: KeyEditor<'_>,
            _: &KeyPatch,
            _: &str,
        ) -> Result<UpdateOutcome> {
            anyhow::bail!("not used by the mint tests")
        }
        async fn revoke_key(
            &self,
            _: &TenantId,
            _: Uuid,
            _: &str,
        ) -> Result<Option<DateTime<Utc>>> {
            anyhow::bail!("not used by the mint tests")
        }
        async fn recorded_spend(
            &self,
            _: &TenantId,
            _: Uuid,
            _: crate::spend::BudgetReset,
        ) -> Option<f64> {
            None
        }
    }

    // ── A13: scope / expiry validation at the mint edge ────────────────────

    /// A minimal VALID scope, for the tests that are not about scope.
    ///
    /// R73 made `scope` required, so scope validation now short-circuits every
    /// other validator on the route. A test about expiry or budget that omitted
    /// scope would stop asserting what it was written to assert and start
    /// asserting the scope refusal — green for the wrong reason, which is the
    /// shape `docs/reference/TRAPS.md` §1 exists for.
    fn a_scope() -> Option<Vec<String>> {
        Some(vec!["chat".into()])
    }

    fn body_with(
        scope: Option<Vec<String>>,
        expires_at: Option<String>,
        budget: Option<f64>,
    ) -> CreateKeyBody {
        CreateKeyBody {
            name: "k".into(),
            scope,
            expires_at,
            budget_usd_monthly: budget,
            rate_limit_rpm: None,
            budget_reset: None,
            velocity_breaker: false,
            project_id: None,
            environment: None,
            policy: None,
        }
    }

    /// **An omitted `scope` is REFUSED with a 400 naming the field** — founder
    /// ruling R73, 2026-08-22.
    ///
    /// This test replaces `omitted_scope_is_recorded_explicitly_not_as_null`,
    /// which asserted the opposite (that omission stored `{chat, read, ingest}`)
    /// together with the hand-maintained literal pin
    /// `assert_eq!(got, vec!["chat", "ingest", "read"])`. **That pin going red is
    /// the design working**, and its own comment said so: it existed so a change
    /// to what "omitted" means would land on a human. It did.
    ///
    /// The pin's real lesson is kept and is now enforced structurally instead:
    /// it read `["admin", "chat", "ingest", "read"]` while `admin` was silently
    /// granted, and was GREEN the whole time, because it had been written to
    /// match the code rather than to state the intent. A default that no longer
    /// exists cannot be pinned to the wrong value.
    #[tokio::test]
    async fn omitted_scope_is_refused_with_400_naming_the_field() {
        let (state, seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, None, None)),
        )
        .await
        .expect_err("an omitted scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(
            err.1.contains("scope is required"),
            "the 400 must name the field — got {:?}",
            err.1
        );
        assert!(
            err.1.contains("chat"),
            "the 400 must list the known scopes — got {:?}",
            err.1
        );
        // THE DISCRIMINATING ASSERTION. A 400 that still minted would be the
        // worst of both: the caller is told no and a credential exists anyway.
        // Asserting the refusal message alone cannot tell those apart.
        assert!(
            seen.lock().expect("seen lock").is_empty(),
            "a refused mint must not reach the minter"
        );
    }

    /// **An omitted scope must NEVER grant `admin`.** `admin` is
    /// *"manage the workspace — mint/revoke keys, provider keys, settings"*, so a
    /// silent grant is the exact escalation `is_verified_owner()` was added to
    /// prevent (/PL-9b), reachable by KEY instead of by JWT.
    ///
    /// R73 makes this hold for a stronger reason than it used to: omission no
    /// longer grants anything at all. **The test is kept rather than deleted**
    /// because it states the PROPERTY, not the mechanism — if a default is ever
    /// reintroduced, this is what stops it carrying `admin` again, and it would
    /// go red on that change rather than on this one.
    #[tokio::test]
    async fn omitted_scope_never_includes_admin() {
        let (state, seen) = mock_state();
        let outcome = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, None, None)),
        )
        .await;
        match outcome {
            // Today: refused outright, so no scope is granted at all.
            Err((status, _)) => assert_eq!(status, StatusCode::BAD_REQUEST),
            // If a default is ever reintroduced, it must not carry `admin`.
            Ok((_status, Json(body))) => {
                let got = body.scope.expect("scope must not be null on a new key");
                assert!(
                    !got.iter().any(|s| s == "admin"),
                    "omitting `scope` must never grant admin — got {got:?}"
                );
            }
        }
        let _ = seen;
    }

    /// grantable when it is asked for BY NAME. Opt-in, not unavailable.
    #[tokio::test]
    async fn admin_scope_is_still_grantable_when_requested_explicitly() {
        let (state, _seen) = mock_state();
        let (status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec!["admin".into()]), None, None)),
        )
        .await
        .expect("an explicit admin scope must still mint");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            body.scope.expect("scope must not be null"),
            vec!["admin".to_string()]
        );
    }

    /// An unknown slug is a 400 naming the problem — never a silent drop that
    /// hands back a key doing less than the caller asked for.
    #[tokio::test]
    async fn unknown_scope_is_rejected_with_the_known_set() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec!["superuser".into()]), None, None)),
        )
        .await
        .expect_err("an unknown scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(
            err.1.contains("superuser"),
            "message must name the bad slug"
        );
        assert!(err.1.contains("chat"), "message must list the known scopes");
    }

    #[tokio::test]
    async fn scope_is_normalised_and_deduplicated() {
        let (state, _seen) = mock_state();
        let (_s, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(
                Some(vec!["READ".into(), " read ".into(), "chat".into()]),
                None,
                None,
            )),
        )
        .await
        .expect("mint should succeed");
        assert_eq!(
            body.scope,
            Some(vec!["read".to_string(), "chat".to_string()])
        );
    }

    /// `{}` is refused rather than stored: the DB CHECK would reject it anyway,
    /// and a 400 explaining the alternative beats a 500 from a constraint.
    #[tokio::test]
    async fn empty_scope_array_is_refused_with_guidance() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec![]), None, None)),
        )
        .await
        .expect_err("an empty scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // R73: the old guidance was "omit it for a full-surface key". Omitting is
        // now itself a 400, so telling the caller to omit would route them into a
        // second refusal. The message must state the vocabulary instead.
        assert!(
            err.1.contains("at least one"),
            "must say a scope is needed — got {:?}",
            err.1
        );
        assert!(
            err.1.contains("chat"),
            "must list the known scopes — got {:?}",
            err.1
        );
    }

    /// Minting an already-dead credential is almost certainly a mistake, and
    /// silently doing it is worse than refusing.
    #[tokio::test]
    async fn past_expiry_is_refused() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(
                a_scope(),
                Some("2020-01-01T00:00:00Z".into()),
                None,
            )),
        )
        .await
        .expect_err("a past expiry must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("future"));
    }

    #[tokio::test]
    async fn malformed_expiry_is_a_400_not_a_500() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(a_scope(), Some("next tuesday".into()), None)),
        )
        .await
        .expect_err("a malformed expiry must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("RFC3339"));
    }

    #[tokio::test]
    async fn negative_and_nonfinite_budgets_are_refused() {
        for bad in [-1.0_f64, f64::NAN, f64::INFINITY] {
            let (state, _seen) = mock_state();
            let err = create_key_handler(
                State(state),
                bearer_headers(),
                Json(body_with(a_scope(), None, Some(bad))),
            )
            .await
            .expect_err("a bad budget must be refused");
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "budget {bad} must 400");
        }
    }

    // ── GWY-43: per-key rate limit at the mint edge ────────────────────────

    /// Every value the DB CHECK would reject must be a 400 HERE, naming the
    /// field. `0` is in the list on purpose: it is the one plausible-looking
    /// value a user might type meaning "off", and it would mint a key that can
    /// never serve a request.
    #[tokio::test]
    async fn zero_negative_and_oversized_rate_limits_are_refused() {
        for bad in [0_i64, -1, i64::from(i32::MAX) + 1] {
            let (state, seen) = mock_state();
            let mut body = body_with(a_scope(), None, None);
            body.rate_limit_rpm = Some(bad);
            let err = create_key_handler(State(state), bearer_headers(), Json(body))
                .await
                .expect_err("a bad rate limit must be refused");
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "rpm {bad} must 400");
            assert!(
                err.1.contains("rate_limit_rpm"),
                "message must name the field — got {:?}",
                err.1
            );
            assert!(
                seen.lock().unwrap().is_empty(),
                "no mint may happen on an invalid rate limit"
            );
        }
    }

    /// The point of the field: a valid value must reach the INSERT. Asserting
    /// only the 201 would pass even if the handler dropped it on the floor —
    /// which is precisely how `budget_usd_monthly` sat in the schema enforcing
    /// nothing (`db::api_keys::KeyAuth` doc). So assert what the minter was
    /// HANDED, and separately that the response echoes it.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn a_valid_rate_limit_reaches_the_minter_and_the_response() {
        let _g = DevAuthGuard::new();
        let (state, _seen, last_opts) = mock_state_capturing();
        let mut body = body_with(a_scope(), None, Some(25.0));
        body.rate_limit_rpm = Some(120);
        let (status, Json(out)) = create_key_handler(State(state), bearer_headers(), Json(body))
            .await
            .expect("mint should succeed");
        assert_eq!(status, StatusCode::CREATED);
        let opts = last_opts
            .lock()
            .unwrap()
            .clone()
            .expect("the minter must have been called");
        assert_eq!(opts.rate_limit_rpm, Some(120), "the INSERT must carry it");
        assert_eq!(opts.budget_usd_monthly, Some(25.0));
        assert_eq!(out.rate_limit_rpm, Some(120));
        assert_eq!(out.budget_usd_monthly, Some(25.0));
    }

    /// Omitting it stays omitted — `NULL` means "inherit the tenant's plan
    /// tier", and inventing a number here would silently cap every new key.
    #[tokio::test]
    async fn an_omitted_rate_limit_stays_null() {
        let (state, _seen, last_opts) = mock_state_capturing();
        let _created = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(a_scope(), None, None)),
        )
        .await
        .expect("mint should succeed");
        let opts = last_opts
            .lock()
            .unwrap()
            .clone()
            .expect("the minter must have been called");
        assert_eq!(opts.rate_limit_rpm, None);
    }

    fn mock_state() -> (KeyRoutesState, Arc<Mutex<Vec<String>>>) {
        let (state, seen, _opts) = mock_state_capturing();
        (state, seen)
    }

    /// Same mock, plus the handle on what the handler actually passed down —
    /// the only way to assert the VALIDATED options rather than just the 201.
    #[allow(clippy::type_complexity)]
    fn mock_state_capturing() -> (
        KeyRoutesState,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Option<crate::db::api_keys::MintOptions>>>,
    ) {
        let seen = Arc::new(Mutex::new(vec![]));
        let last_opts = Arc::new(Mutex::new(None));
        let state = KeyRoutesState {
            minter: Arc::new(MockKeyMinter {
                seen: seen.clone(),
                last_opts: last_opts.clone(),
            }),
        };
        (state, seen, last_opts)
    }

    /// Replicates the trace_reads dev-auth guard: the dev-stub claims path needs
    /// `WORKOS_CLIENT_ID` unset. Restores it on drop so the suite stays hermetic.
    struct DevAuthGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Option<String>,
    }
    impl DevAuthGuard {
        fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let saved = std::env::var("WORKOS_CLIENT_ID").ok();
            if saved.is_some() {
                unsafe {
                    std::env::remove_var("WORKOS_CLIENT_ID");
                }
            }
            Self { _lock, saved }
        }
    }
    impl Drop for DevAuthGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.saved {
                unsafe {
                    std::env::set_var("WORKOS_CLIENT_ID", v);
                }
            }
        }
    }

    fn bearer_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer dev-token".parse().unwrap(),
        );
        h
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn mint_uses_claims_tenant_and_returns_raw_key() {
        let _g = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let (status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(CreateKeyBody {
                name: "  prod-agent  ".into(),
                // R73: scope is required, and this test is about the TENANT bind
                // and name trimming — leaving it `None` would make it assert the
                // scope refusal instead, which is a different property.
                scope: a_scope(),
                expires_at: None,
                budget_usd_monthly: None,
                rate_limit_rpm: None,
                budget_reset: None,
                velocity_breaker: false,
                project_id: None,
                environment: None,
                policy: None,
            }),
        )
        .await
        .expect("mint should succeed");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.raw_key, "tlane_MOCKKEYBODYdonotuseinprod");
        assert_eq!(body.key_prefix, "AbC012");
        assert_eq!(body.name, "prod-agent", "name is trimmed before minting");
        assert!(body.last_used_at.is_none());
        // The tenant handed to the minter is the validated Claims tenant — never
        // a body/header value.
        assert_eq!(*seen.lock().unwrap(), vec![DEV_TENANT.to_string()]);
    }

    #[tokio::test]
    async fn mint_without_auth_is_401_and_never_mints() {
        let (state, seen) = mock_state();
        let (status, _msg) = create_key_handler(
            State(state),
            HeaderMap::new(), // no Authorization
            Json(CreateKeyBody {
                name: "x".into(),
                scope: None,
                expires_at: None,
                budget_usd_monthly: None,
                rate_limit_rpm: None,
                budget_reset: None,
                velocity_breaker: false,
                project_id: None,
                environment: None,
                policy: None,
            }),
        )
        .await
        .expect_err("must reject unauthenticated");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            seen.lock().unwrap().is_empty(),
            "no mint may happen on an auth failure"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn mint_rejects_blank_name() {
        let _g = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let (status, _msg) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(CreateKeyBody {
                name: "   ".into(),
                scope: None,
                expires_at: None,
                budget_usd_monthly: None,
                rate_limit_rpm: None,
                budget_reset: None,
                velocity_breaker: false,
                project_id: None,
                environment: None,
                policy: None,
            }),
        )
        .await
        .expect_err("blank name must be rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            seen.lock().unwrap().is_empty(),
            "no mint may happen on an invalid name"
        );
    }
}

/// SET-38 (B2) and B-586 (B6) at the ROUTE: who may call, what reaches the
/// store, and what each outcome looks like on the wire. Claims are injected with
/// `auth::test_claims` so every principal — owner, member, viewer, role-less JWT,
/// `tlane_` key, operator — is exercised without WorkOS. Every must-accept has
/// its must-reject beside it.
#[cfg(test)]
mod set38_tests {
    use super::*;
    use crate::auth::{AuthMethod, Claims, Role, test_claims};
    use chrono::{DateTime, Utc};
    use std::sync::Mutex;
    use tower::ServiceExt;
    use uuid::Uuid;

    const TENANT: &str = "00000000-0000-0000-0000-0000000000aa";
    const KEY: &str = "11111111-1111-1111-1111-111111111111";

    /// What the store was asked to do.
    #[derive(Debug, Clone, PartialEq)]
    // `KeyPatch` grows with the key's editable columns; boxing it would only obscure the asserts.
    #[allow(clippy::large_enum_variant)]
    enum Call {
        Get(String, Uuid),
        Update(String, Uuid, String, KeyPatch, String),
        Revoke(String, Uuid, String),
        Spend(String, Uuid),
    }

    struct EditMock {
        calls: Arc<Mutex<Vec<Call>>>,
        update: Mutex<Option<Result<UpdateOutcome>>>,
        revoke: Mutex<Option<Result<Option<DateTime<Utc>>>>>,
        found: bool,
        spend: Option<f64>,
    }

    fn record() -> KeyRecord {
        KeyRecord {
            id: Uuid::parse_str(KEY).unwrap(),
            name: "ci-nightly".into(),
            key_prefix: "ab12cd".into(),
            created_at: DateTime::from_timestamp(1_778_000_000, 0).unwrap(),
            last_used_at: None,
            minted_by: Some("user_owner".into()),
            scope: Some(vec!["chat".into()]),
            expires_at: None,
            budget_usd_monthly: Some(50.0),
            rate_limit_rpm: Some(20),
            budget_reset: crate::spend::BudgetReset::Weekly,
            velocity_breaker: false,
            revoked_at: None,
            project_id: None,
            environment: None,
            policy: None,
            cache: None,
        }
    }

    #[async_trait::async_trait]
    impl KeyMinter for EditMock {
        async fn rotation_grace_hours(&self) -> Result<i64> {
            anyhow::bail!("unused")
        }
        async fn rotate(
            &self,
            _: &TenantId,
            _: Uuid,
            _: &str,
            _: i64,
        ) -> Result<Option<crate::db::api_keys::RotatedKey>> {
            anyhow::bail!("unused")
        }
        async fn mint(
            &self,
            _: &TenantId,
            _: &str,
            _: Option<&str>,
            _: crate::db::api_keys::MintOptions,
        ) -> Result<MintedKey> {
            anyhow::bail!("unused")
        }
        async fn get_key(&self, tenant: &TenantId, id: Uuid) -> Result<Option<KeyRecord>> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Get(tenant.to_string(), id));
            Ok(self.found.then(record))
        }
        async fn update_key(
            &self,
            tenant: &TenantId,
            id: Uuid,
            editor: KeyEditor<'_>,
            patch: &KeyPatch,
            actor: &str,
        ) -> Result<UpdateOutcome> {
            let editor = match editor {
                KeyEditor::Any => "any".to_string(),
                KeyEditor::MintedBy(s) => format!("minted_by:{s}"),
            };
            self.calls.lock().unwrap().push(Call::Update(
                tenant.to_string(),
                id,
                editor,
                patch.clone(),
                actor.to_string(),
            ));
            self.update.lock().unwrap().take().unwrap_or_else(|| {
                Ok(UpdateOutcome::Updated {
                    record: Box::new(record()),
                    changed: vec!["rate_limit_rpm"],
                })
            })
        }
        async fn revoke_key(
            &self,
            tenant: &TenantId,
            id: Uuid,
            actor: &str,
        ) -> Result<Option<DateTime<Utc>>> {
            self.calls.lock().unwrap().push(Call::Revoke(
                tenant.to_string(),
                id,
                actor.to_string(),
            ));
            self.revoke
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(Some(Utc::now())))
        }
        async fn recorded_spend(
            &self,
            tenant: &TenantId,
            key_id: Uuid,
            _: crate::spend::BudgetReset,
        ) -> Option<f64> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Spend(tenant.to_string(), key_id));
            self.spend
        }
    }

    fn mock_with(found: bool, spend: Option<f64>) -> (Arc<EditMock>, Arc<Mutex<Vec<Call>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let m = Arc::new(EditMock {
            calls: calls.clone(),
            update: Mutex::new(None),
            revoke: Mutex::new(None),
            found,
            spend,
        });
        (m, calls)
    }

    fn mock() -> (Arc<EditMock>, Arc<Mutex<Vec<Call>>>) {
        mock_with(true, Some(12.4))
    }

    fn claims(method: AuthMethod, role: Option<Role>, sub: &str) -> Claims {
        Claims {
            tenant_id: TenantId::from_jwt_claim(Uuid::parse_str(TENANT).unwrap()),
            sub: sub.into(),
            auth_method: method,
            role,
            key_scope: tracelane_shared::api_scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        }
    }
    fn owner() -> Claims {
        claims(AuthMethod::JwtBearer, Some(Role::Owner), "user_owner")
    }
    fn member() -> Claims {
        claims(AuthMethod::JwtBearer, Some(Role::Member), "user_member")
    }
    fn viewer() -> Claims {
        claims(AuthMethod::JwtBearer, Some(Role::Viewer), "user_viewer")
    }
    fn roleless_jwt() -> Claims {
        claims(AuthMethod::JwtBearer, None, "user_nobody")
    }
    /// A `tlane_` key — including the very key being edited (`apikey:<KEY>`).
    fn api_key_itself() -> Claims {
        claims(AuthMethod::ApiKey, None, &format!("apikey:{KEY}"))
    }
    fn operator() -> Claims {
        claims(AuthMethod::SelfHostMasterKey, None, "self-host")
    }

    /// Send one request through the real router. `who = None` sends NO
    /// Authorization header (the 401 path); otherwise the claims are injected.
    async fn send(
        m: Arc<EditMock>,
        who: Option<Claims>,
        method: &str,
        path: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let _guard = who.clone().map(test_claims::Guard::set);
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if who.is_some() {
            req = req.header("authorization", "Bearer unit-test-token-not-real");
        }
        let resp = routes()
            .with_state(KeyRoutesState { minter: m })
            .oneshot(req.body(axum::body::Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn key_path() -> String {
        format!("/v1/keys/{KEY}")
    }

    fn updates(calls: &Arc<Mutex<Vec<Call>>>) -> Vec<Call> {
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| matches!(c, Call::Update(..)))
            .cloned()
            .collect()
    }

    // ── PATCH: who may edit ────────────────────────────────────────────────

    #[tokio::test]
    async fn patch_without_credentials_is_401_and_touches_nothing() {
        let (m, calls) = mock();
        let (s, _) = send(m, None, "PATCH", &key_path(), r#"{"rate_limit_rpm":2}"#).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(calls.lock().unwrap().is_empty());
    }

    /// Must REJECT: viewer, a JWT with no recognised role, an mTLS identity, and a
    /// `tlane_` key — including the key editing ITSELF (a capped key must never
    /// lift its own cap). Each is a 403 `role_forbidden` that never reaches the store.
    #[tokio::test]
    async fn patch_refuses_viewer_roleless_jwt_mtls_and_any_api_key() {
        for who in [
            viewer(),
            roleless_jwt(),
            api_key_itself(),
            claims(AuthMethod::Mtls, None, "spiffe://x"),
        ] {
            let (m, calls) = mock();
            let label = format!("{:?}/{:?}", who.auth_method, who.role);
            let (s, body) = send(
                m,
                Some(who),
                "PATCH",
                &key_path(),
                r#"{"budget_usd_monthly":1000000}"#,
            )
            .await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{label} must be refused");
            assert_eq!(body["error"], "role_forbidden", "{label}");
            assert!(
                calls.lock().unwrap().is_empty(),
                "{label}: a refused caller must never reach the store"
            );
        }
    }

    /// Must ACCEPT: owner and operator edit ANY key; a member reaches the store
    /// only as `MintedBy(their own sub)`, which the row lock then enforces. The
    /// tenant handed down is the CLAIMS tenant, and the actor is the claims `sub`.
    #[tokio::test]
    async fn patch_passes_the_right_editor_and_the_claims_tenant() {
        for (who, editor) in [
            (owner(), "any".to_string()),
            (operator(), "any".to_string()),
            (member(), "minted_by:user_member".to_string()),
        ] {
            let (m, calls) = mock();
            let sub = who.sub.clone();
            let (s, body) = send(
                m,
                Some(who),
                "PATCH",
                &key_path(),
                r#"{"rate_limit_rpm":2}"#,
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{editor}");
            assert_eq!(body["changed"], serde_json::json!(["rate_limit_rpm"]));
            assert_eq!(body["rateLimitRpm"], 20, "the response is the stored row");
            assert!(
                body.get("rawKey").is_none(),
                "an edit never reveals a secret"
            );
            let got = updates(&calls);
            assert_eq!(got.len(), 1);
            let Call::Update(tenant, id, ed, patch, actor) = &got[0] else {
                unreachable!()
            };
            assert_eq!(tenant, TENANT, "tenant from the claims, never the request");
            assert_eq!(id.to_string(), KEY);
            assert_eq!(ed, &editor);
            assert_eq!(actor, &sub);
            assert_eq!(patch.rate_limit_rpm, Some(Some(2)));
        }
    }

    /// H1 (security review 2026-10-02): `passthrough` sends raw, unscanned bodies to a
    /// provider, so granting it is an OWNER decision. A member could previously mint a
    /// passthrough key for themselves, or add the scope to their own key by PATCH.
    #[tokio::test]
    async fn h1_a_member_cannot_grant_passthrough_on_create_or_edit() {
        // PATCH: refused before the store is reached.
        let (m, calls) = mock();
        let (s, body) = send(
            m,
            Some(member()),
            "PATCH",
            &key_path(),
            r#"{"scope":["chat","passthrough"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "role_forbidden");
        assert_eq!(body["required_role"], "owner");
        assert!(calls.lock().unwrap().is_empty(), "never reaches the store");
        // POST: refused before minting.
        let (m, calls) = mock();
        let (s, body) = send(
            m,
            Some(member()),
            "POST",
            "/v1/keys",
            r#"{"name":"k","scope":["passthrough"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
        assert!(calls.lock().unwrap().is_empty());
        // Must ACCEPT: a member's scope edit without passthrough still reaches the store,
        // and an owner may grant passthrough.
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(member()),
            "PATCH",
            &key_path(),
            r#"{"scope":["chat"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(updates(&calls).len(), 1);
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(owner()),
            "PATCH",
            &key_path(),
            r#"{"scope":["chat","passthrough"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(updates(&calls).len(), 1);
        // The self-host operator (master key) IS the deployment's owner and has no role
        // system. Unreachable in a real self-host today (no Postgres ⇒ no key routes; see
        // `scope_refusal`); pinned so the arm stays owner-equivalent.
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(operator()),
            "PATCH",
            &key_path(),
            r#"{"scope":["chat","passthrough"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(updates(&calls).len(), 1);
        // ...and a tenant `tlane_` key (PL-9b: never admin) still cannot self-grant.
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(api_key_itself()),
            "PATCH",
            &key_path(),
            r#"{"scope":["chat","passthrough"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(calls.lock().unwrap().is_empty());
    }

    /// rev5 H1: an `admin`-scoped key holds the matrix's `api_key` column (`edit_budgets`,
    /// `write_prompts`), which a developer does not — so a developer may not mint one, nor
    /// add the scope to their own key. A key never holds more than its minter's role allows.
    #[tokio::test]
    async fn rev5_h1_a_developer_cannot_grant_the_admin_scope_on_create_or_edit() {
        for body in [r#"{"scope":["chat","admin"]}"#, r#"{"scope":["admin"]}"#] {
            let (m, calls) = mock();
            let (s, j) = send(m, Some(member()), "PATCH", &key_path(), body).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "PATCH {body}: {j}");
            assert_eq!(j["error"], "role_forbidden");
            assert!(calls.lock().unwrap().is_empty(), "never reaches the store");
            let mint = format!(r#"{{"name":"k",{}"#, &body[1..]);
            let (m, calls) = mock();
            let (s, j) = send(m, Some(member()), "POST", "/v1/keys", &mint).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "POST {mint}: {j}");
            assert!(calls.lock().unwrap().is_empty(), "nothing minted");
        }
        // Must ACCEPT: an admin (and the operator) may grant it; a developer may still
        // mint and edit within the developer's own reach.
        for who in [owner(), operator()] {
            let (m, calls) = mock();
            let (s, _) = send(m, Some(who), "PATCH", &key_path(), r#"{"scope":["admin"]}"#).await;
            assert_eq!(s, StatusCode::OK);
            assert_eq!(updates(&calls).len(), 1);
        }
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(member()),
            "PATCH",
            &key_path(),
            r#"{"scope":["chat","read","ingest"]}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(updates(&calls).len(), 1);
    }

    /// rev5 H1, the property: EVERY scope set a developer is allowed to mint yields a key
    /// that the budget and prompt / dataset / experiment / online-eval write gates refuse.
    /// The mintable sets are derived from the mint gate itself (every subset of every
    /// scope), so a scope added later is covered without editing this test.
    #[test]
    fn rev5_h1_no_key_a_developer_can_mint_reaches_budgets_or_prompt_writes() {
        use tracelane_shared::api_scope::Scope;
        let all = Scope::all();
        let dev = member();
        let mut mintable = 0;
        for mask in 1u32..(1 << all.len()) {
            let set: std::collections::BTreeSet<Scope> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| *s)
                .collect();
            let slugs: Vec<String> = set.iter().map(|s| s.as_slug().to_owned()).collect();
            if scope_refusal(&dev, &slugs).is_some() {
                continue;
            }
            mintable += 1;
            let key = crate::auth::Claims {
                key_scope: crate::auth::scope::KeyScope::Scoped(set.clone()),
                ..claims(AuthMethod::ApiKey, None, "apikey:dev-minted")
            };
            assert!(
                crate::billing::usage::authorize_budget_edit(&key).is_err(),
                "{slugs:?}: a developer-minted key moved a budget"
            );
            assert!(
                crate::prompt_routes::authorize_write(&key).is_err(),
                "{slugs:?}: a developer-minted key promoted a prompt"
            );
            assert!(
                crate::dataset_routes::authorize_write(&key).is_err(),
                "{slugs:?}: a developer-minted key wrote a dataset"
            );
            assert!(
                crate::experiment_routes::authorize_write(&key).is_err(),
                "{slugs:?}: a developer-minted key started an experiment"
            );
            assert!(
                crate::online_eval_routes::require_writer(&key).is_err(),
                "{slugs:?}: a developer-minted key changed the online-eval policy"
            );
        }
        assert_eq!(mintable, 7, "chat/read/ingest and their non-empty subsets");
        // ...and an admin may mint an `admin` key (the gate is the minter's role).
        assert!(scope_refusal(&owner(), &["admin".to_owned()]).is_none());
    }

    /// OG-20 / OG-23: a key's project, environment and policy are OWNER decisions — a
    /// member must not lift a restriction on a key they minted — and an invalid policy is a
    /// 400 naming the entry, never stored. Refused before the store on every path.
    #[tokio::test]
    async fn og20_only_an_owner_sets_a_keys_policy_project_or_environment() {
        let project = "00000000-0000-0000-0000-0000000000aa";
        for body in [
            r#"{"policy":{"models":{"allow":["gpt-4o"]}}}"#.to_owned(),
            r#"{"policy":null}"#.to_owned(),
            format!(r#"{{"project_id":"{project}"}}"#),
            r#"{"environment":"staging"}"#.to_owned(),
        ] {
            for who in [member(), api_key_itself(), viewer()] {
                let (m, calls) = mock();
                let (s, j) = send(m, Some(who), "PATCH", &key_path(), &body).await;
                assert_eq!(s, StatusCode::FORBIDDEN, "{body}: {j}");
                assert!(calls.lock().unwrap().is_empty(), "never reaches the store");
            }
            // POST with the same field (a value, not a clear) is refused for a member too.
            if body.contains("null") {
                continue;
            }
            let (m, _) = mock();
            let post = body.replacen('{', r#"{"name":"k","scope":["chat"],"#, 1);
            let (s, j) = send(m, Some(member()), "POST", "/v1/keys", &post).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{post}: {j}");
        }
        // An owner reaches the store, with the policy CANONICAL (lower-cased).
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(owner()),
            "PATCH",
            &key_path(),
            r#"{"policy":{"models":{"allow":["GPT-4o"]}},"environment":"staging"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let ups = updates(&calls);
        assert_eq!(ups.len(), 1);
        let Call::Update(_, _, _, patch, _) = &ups[0] else {
            unreachable!()
        };
        assert_eq!(
            patch.policy,
            Some(Some(serde_json::json!({"models": {"allow": ["gpt-4o"]}})))
        );
        assert_eq!(patch.environment, Some(Some("staging".to_owned())));
        // Invalid entries are 400s naming the field, before the store.
        for (body, field) in [
            (
                r#"{"policy":{"models":{"allow":["has space"]}}}"#,
                "policy.models.allow",
            ),
            (r#"{"policy":{"unknown_rule":1}}"#, "policy"),
            (r#"{"policy":{}}"#, "policy"),
            (r#"{"environment":"Prod"}"#, "environment"),
            (r#"{"project_id":"not-a-uuid"}"#, "project_id"),
        ] {
            let (m, calls) = mock();
            let (s, j) = send(m, Some(owner()), "PATCH", &key_path(), body).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {j}");
            assert_eq!(j["field"], field, "{body}: {j}");
            assert!(calls.lock().unwrap().is_empty());
        }
    }

    /// OG-23: the store's assignment refusals reach the caller as 404 / 409 / 400 — another
    /// tenant's project is exactly an absent one.
    #[tokio::test]
    async fn og23_assignment_refusals_map_to_their_codes() {
        for (outcome, status, code) in [
            (
                UpdateOutcome::ProjectNotFound,
                StatusCode::NOT_FOUND,
                "project_not_found",
            ),
            (
                UpdateOutcome::EnvironmentNotInProject {
                    environment: "qa".into(),
                },
                StatusCode::CONFLICT,
                "environment_not_in_project",
            ),
            (
                UpdateOutcome::EnvironmentNeedsProject,
                StatusCode::BAD_REQUEST,
                "invalid_field",
            ),
        ] {
            let (m, _) = mock();
            *m.update.lock().unwrap() = Some(Ok(outcome));
            let (s, j) = send(
                m,
                Some(owner()),
                "PATCH",
                &key_path(),
                r#"{"project_id":"00000000-0000-0000-0000-0000000000aa"}"#,
            )
            .await;
            assert_eq!((s, j["error"].as_str()), (status, Some(code)), "{j}");
        }
    }

    /// A member editing a key someone else minted: the store says Forbidden under
    /// the row lock, and the route answers 403 naming `owner`.
    #[tokio::test]
    async fn patch_member_on_someone_elses_key_is_403() {
        let (m, _) = mock();
        *m.update.lock().unwrap() = Some(Ok(UpdateOutcome::Forbidden));
        let (s, body) = send(
            m,
            Some(member()),
            "PATCH",
            &key_path(),
            r#"{"rate_limit_rpm":1}"#,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "role_forbidden");
        assert_eq!(body["required_role"], "owner");
    }

    /// Another tenant's key id, a revoked key, an expired key: all one 404.
    /// A retiring key: 409 `key_retiring`. A store failure: 500 "nothing was changed".
    #[tokio::test]
    async fn patch_maps_every_store_outcome() {
        let cases: Vec<(Result<UpdateOutcome>, StatusCode, &str)> = vec![
            (
                Ok(UpdateOutcome::NotFound),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                Ok(UpdateOutcome::Retiring {
                    revoked_at: DateTime::from_timestamp(1_900_000_000, 0).unwrap(),
                }),
                StatusCode::CONFLICT,
                "key_retiring",
            ),
            (
                Err(anyhow::anyhow!("audit insert refused")),
                StatusCode::INTERNAL_SERVER_ERROR,
                "not_saved",
            ),
        ];
        for (outcome, status, code) in cases {
            let (m, _) = mock();
            *m.update.lock().unwrap() = Some(outcome);
            let (s, body) = send(
                m,
                Some(owner()),
                "PATCH",
                &key_path(),
                r#"{"rate_limit_rpm":1}"#,
            )
            .await;
            assert_eq!(s, status, "{code}");
            assert_eq!(body["error"], code);
            if code == "not_saved" {
                assert!(
                    body["message"]
                        .as_str()
                        .unwrap()
                        .contains("nothing was changed")
                );
            }
            if code == "key_retiring" {
                assert!(body["message"].as_str().unwrap().contains("successor"));
            }
        }
    }

    // ── PATCH: what may be sent ────────────────────────────────────────────

    /// Every refused body is a 400 that NEVER reaches the store: a smuggled
    /// `tenant_id`, `scope: null` (re-entering legacy), a past expiry, an
    /// out-of-range budget and rate limit, an unknown scope, a cleared name, an
    /// empty patch, and a non-object.
    #[tokio::test]
    async fn patch_refusals_are_400_and_never_reach_the_store() {
        let cases = [
            (
                r#"{"tenant_id":"00000000-0000-0000-0000-0000000000bb","rate_limit_rpm":2}"#,
                "invalid_body",
                None,
            ),
            (
                r#"{"scope":null}"#,
                "scope_cannot_become_legacy",
                Some("scope"),
            ),
            (
                r#"{"expires_at":"2020-01-01T00:00:00Z"}"#,
                "invalid_field",
                Some("expires_at"),
            ),
            (
                r#"{"expires_at":"next tuesday"}"#,
                "invalid_field",
                Some("expires_at"),
            ),
            (
                r#"{"budget_usd_monthly":-1}"#,
                "invalid_field",
                Some("budget_usd_monthly"),
            ),
            (
                r#"{"rate_limit_rpm":0}"#,
                "invalid_field",
                Some("rate_limit_rpm"),
            ),
            (
                r#"{"rate_limit_rpm":2147483648}"#,
                "invalid_field",
                Some("rate_limit_rpm"),
            ),
            (r#"{"scope":["superuser"]}"#, "invalid_field", Some("scope")),
            (r#"{"scope":[]}"#, "invalid_field", Some("scope")),
            (r#"{"name":null}"#, "invalid_field", Some("name")),
            (r#"{"name":"   "}"#, "invalid_field", Some("name")),
            (
                r#"{"budget_reset":"hourly"}"#,
                "invalid_field",
                Some("budget_reset"),
            ),
            (
                r#"{"budget_reset":null}"#,
                "invalid_field",
                Some("budget_reset"),
            ),
            (
                r#"{"velocity_breaker":null}"#,
                "invalid_field",
                Some("velocity_breaker"),
            ),
            (r#"{}"#, "nothing_to_change", None),
            (r#"[]"#, "invalid_body", None),
            // serde would read this positionally as `{"name":"renamed"}`.
            (r#"["renamed"]"#, "invalid_body", None),
            (r#""#, "invalid_body", None),
        ];
        for (body, code, field) in cases {
            let (m, calls) = mock();
            let (s, out) = send(m, Some(owner()), "PATCH", &key_path(), body).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(out["error"], code, "{body}");
            if let Some(f) = field {
                assert_eq!(out["field"], f, "{body} must name the field");
            }
            assert!(
                updates(&calls).is_empty(),
                "{body} must not reach the store"
            );
        }
    }

    /// The past-expiry message tells the user what they probably meant.
    #[tokio::test]
    async fn patch_past_expiry_points_at_revoke() {
        let (m, _) = mock();
        let (_, out) = send(
            m,
            Some(owner()),
            "PATCH",
            &key_path(),
            r#"{"expires_at":"2020-01-01T00:00:00Z"}"#,
        )
        .await;
        assert!(out["message"].as_str().unwrap().contains("revoke it"));
    }

    /// Must ACCEPT: absent = unchanged, `null` = clear, value = set — and a scope
    /// is normalised by create's own validator before it reaches the store.
    #[tokio::test]
    async fn patch_merge_semantics_reach_the_store_exactly() {
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(owner()),
            "PATCH",
            &key_path(),
            r#"{"budget_usd_monthly":null,"rate_limit_rpm":null,"expires_at":null,
                "scope":["READ"," read ","chat"],"budget_reset":"daily",
                "velocity_breaker":true,"name":"  renamed  "}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let Call::Update(_, _, _, patch, _) = &updates(&calls)[0] else {
            unreachable!()
        };
        assert_eq!(
            patch,
            &KeyPatch {
                name: Some("renamed".into()),
                scope: Some(vec!["read".into(), "chat".into()]),
                expires_at: Some(None),
                budget_usd_monthly: Some(None),
                rate_limit_rpm: Some(None),
                budget_reset: Some(crate::spend::BudgetReset::Daily),
                velocity_breaker: Some(true),
                project_id: None,
                environment: None,
                policy: None,
                cache: None,
            }
        );
        // An absent field stays absent.
        let (m, calls) = mock();
        send(
            m,
            Some(owner()),
            "PATCH",
            &key_path(),
            r#"{"rate_limit_rpm":5}"#,
        )
        .await;
        let Call::Update(_, _, _, patch, _) = &updates(&calls)[0] else {
            unreachable!()
        };
        assert_eq!(
            patch,
            &KeyPatch {
                rate_limit_rpm: Some(Some(5)),
                ..Default::default()
            }
        );
    }

    /// A path id that is not a UUID: 404 for an authenticated caller, 401 for an
    /// anonymous one (auth runs first).
    #[tokio::test]
    async fn a_non_uuid_id_is_404_after_auth_and_401_before() {
        let (m, calls) = mock();
        let (s, _) = send(
            m,
            Some(owner()),
            "PATCH",
            "/v1/keys/not-a-uuid",
            r#"{"rate_limit_rpm":2}"#,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(calls.lock().unwrap().is_empty());
        let (m, _) = mock();
        let (s, _) = send(m, None, "PATCH", "/v1/keys/not-a-uuid", "{}").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    // ── GET /v1/keys/{id} ─────────────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_the_row_and_this_windows_recorded_spend() {
        for who in [owner(), member(), viewer(), operator()] {
            let (m, calls) = mock();
            let (s, body) = send(m, Some(who), "GET", &key_path(), "").await;
            assert_eq!(s, StatusCode::OK);
            assert_eq!(body["name"], "ci-nightly");
            assert_eq!(body["budgetReset"], "weekly");
            assert_eq!(body["spend"]["window"], "week");
            assert_eq!(body["spend"]["recorded_usd"], 12.4);
            assert!(body.get("rawKey").is_none());
            let seen = calls.lock().unwrap().clone();
            let key = Uuid::parse_str(KEY).unwrap();
            assert_eq!(
                seen,
                vec![
                    Call::Get(TENANT.into(), key),
                    Call::Spend(TENANT.into(), key)
                ],
                "tenant from the claims for BOTH reads"
            );
        }
    }

    /// Unknown spend is `null`, NEVER `0` — and a true zero stays `0`.
    #[tokio::test]
    async fn get_reports_unknown_spend_as_null_and_a_true_zero_as_zero() {
        for (spend, want) in [
            (None, serde_json::Value::Null),
            (Some(0.0), serde_json::json!(0.0)),
        ] {
            let (m, _) = mock_with(true, spend);
            let (s, body) = send(m, Some(owner()), "GET", &key_path(), "").await;
            assert_eq!(s, StatusCode::OK);
            assert_eq!(body["spend"]["recorded_usd"], want);
        }
    }

    #[tokio::test]
    async fn get_refuses_api_keys_and_roleless_jwts_and_404s_a_missing_key() {
        for who in [api_key_itself(), roleless_jwt()] {
            let (m, calls) = mock();
            let (s, _) = send(m, Some(who), "GET", &key_path(), "").await;
            assert_eq!(s, StatusCode::FORBIDDEN);
            assert!(calls.lock().unwrap().is_empty());
        }
        let (m, _) = mock();
        let (s, _) = send(m, None, "GET", &key_path(), "").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (m, _) = mock_with(false, Some(1.0));
        let (s, body) = send(m, Some(owner()), "GET", &key_path(), "").await;
        assert_eq!(
            s,
            StatusCode::NOT_FOUND,
            "another tenant's key reads as absent"
        );
        assert_eq!(body["error"], "not_found");
    }

    /// The window start is the UTC boundary the ClickHouse query reads from.
    #[test]
    fn window_start_matches_the_clickhouse_boundaries() {
        let now = DateTime::parse_from_rfc3339("2026-09-27T15:04:05Z")
            .unwrap()
            .with_timezone(&Utc); // a Sunday
        let at = |c| {
            let (label, t) = window_start(c, now);
            (label, t.to_rfc3339())
        };
        assert_eq!(
            at(crate::spend::BudgetReset::Daily),
            ("day", "2026-09-27T00:00:00+00:00".into())
        );
        assert_eq!(
            at(crate::spend::BudgetReset::Weekly),
            ("week", "2026-09-21T00:00:00+00:00".into()),
            "ISO week: Monday 00:00 UTC"
        );
        assert_eq!(
            at(crate::spend::BudgetReset::Monthly),
            ("month", "2026-09-01T00:00:00+00:00".into())
        );
    }

    /// The production spend read fails to `None` — never `Some(0.0)` — when
    /// ClickHouse is absent or unreachable.
    #[tokio::test]
    async fn recorded_spend_is_none_when_clickhouse_is_absent_or_unreachable() {
        let tenant = TenantId::from_jwt_claim(Uuid::parse_str(TENANT).unwrap());
        let key = Uuid::parse_str(KEY).unwrap();
        assert_eq!(
            recorded_spend_from_clickhouse(
                None,
                None,
                &tenant,
                key,
                crate::spend::BudgetReset::Monthly
            )
            .await,
            None
        );
        // Port 9 (discard) on loopback: refused at once; nothing leaves the box.
        assert_eq!(
            recorded_spend_from_clickhouse(
                Some("http://127.0.0.1:9"),
                None,
                &tenant,
                key,
                crate::spend::BudgetReset::Monthly
            )
            .await,
            None,
            "an unreadable spend must be unknown, never $0.00"
        );
    }

    // ── DELETE /v1/keys/{id} (B-586) ───────────────────────────────────────

    #[tokio::test]
    async fn delete_by_an_owner_revokes_in_the_claims_tenant() {
        for who in [owner(), operator()] {
            let (m, calls) = mock();
            let sub = who.sub.clone();
            let (s, _) = send(m, Some(who), "DELETE", &key_path(), "").await;
            assert_eq!(s, StatusCode::NO_CONTENT);
            assert_eq!(
                calls.lock().unwrap().clone(),
                vec![Call::Revoke(
                    TENANT.into(),
                    Uuid::parse_str(KEY).unwrap(),
                    sub
                )]
            );
        }
    }

    /// Must REJECT: a member (revoke is owner-only, as the web route always was),
    /// a viewer, a role-less JWT, and any `tlane_` key.
    #[tokio::test]
    async fn delete_refuses_member_viewer_roleless_and_api_keys() {
        for who in [member(), viewer(), roleless_jwt(), api_key_itself()] {
            let (m, calls) = mock();
            let (s, body) = send(m, Some(who), "DELETE", &key_path(), "").await;
            assert_eq!(s, StatusCode::FORBIDDEN);
            assert_eq!(body["required_role"], "owner");
            assert!(calls.lock().unwrap().is_empty());
        }
        let (m, _) = mock();
        let (s, _) = send(m, None, "DELETE", &key_path(), "").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_maps_missing_and_failed_revocations() {
        let (m, _) = mock();
        *m.revoke.lock().unwrap() = Some(Ok(None));
        let (s, body) = send(m, Some(owner()), "DELETE", &key_path(), "").await;
        assert_eq!(
            s,
            StatusCode::NOT_FOUND,
            "another tenant's / already revoked"
        );
        assert_eq!(body["error"], "not_found");
        let (m, _) = mock();
        *m.revoke.lock().unwrap() = Some(Err(anyhow::anyhow!("audit refused")));
        let (s, body) = send(m, Some(owner()), "DELETE", &key_path(), "").await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "not_revoked");
    }
}
