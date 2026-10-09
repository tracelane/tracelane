//! `OG-50` — `/v1/exports/otel`: manage a workspace's OTLP/HTTP span exports
//! (`specs/OG-50-otel-export.md` §2). The runtime is [`crate::otel_export`].
//!
//! | Route | Who | Audit |
//! |---|---|---|
//! | `GET /v1/exports/otel` — header NAMES (never values), the URL as host + path | capability `view_policies` | — |
//! | `POST /v1/exports/otel` `{name, url, headers?, include_content?, sample_ratio?, only_errors?}` | `edit_policies` | `otel_export.create` |
//! | `PATCH /v1/exports/otel/{id}` `{enabled?, include_content?, sample_ratio?, only_errors?, headers?}` | `edit_policies` | `otel_export.update` |
//! | `DELETE /v1/exports/otel/{id}` | `edit_policies` | `otel_export.delete` |
//! | `POST /v1/exports/otel/{id}/test` — one synthetic span, a class and a latency | `edit_policies` | none (no state changes) |
//!
//! Registered in `CONTROL_ROUTES`; every write goes through `control_plane::require_control`
//! (capability, admin IP allowlist, SSO-required) and records ONE `admin_audit_log` row in
//! the change's own transaction. An API key never manages exports. The tenant is
//! `claims.tenant_id` ONLY. Mounted only with a Postgres control plane.
//!
//! **Plan gate (fail-CLOSED, `.claude/rules/tenancy.md`):** a write needs the plan's
//! `f_otel_export` (seeded OFF for every plan until the founder rules, spec §9); no
//! entitlement read at all is refused too. `max_exports` caps the count.
//!
//! **Secrets:** header values are sealed (`db::otel_exports`, AAD `otel-export:<tenant>:<id>`)
//! before they reach the database and appear in NO response, log or audit row.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::Claims;
use crate::auth::capability::Capability;
use crate::db::otel_exports::{self as store, CreateOutcome, Export, NewExport, Patch};
use crate::otel_export as runtime;
use crate::server::AppState;

/// Mounted only when a Postgres control plane exists (`server.rs`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/exports/otel", get(list_exports).post(create_export))
        .route(
            "/v1/exports/otel/{id}",
            axum::routing::patch(update_export).delete(delete_export),
        )
        .route("/v1/exports/otel/{id}/test", post(test_export))
        .with_state(state)
}

fn error(status: StatusCode, code: &str, message: &str, field: Option<&str>) -> Response {
    let mut body = json!({ "error": code, "message": message });
    if let Some(f) = field {
        body["field"] = json!(f);
    }
    (
        status,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(body),
    )
        .into_response()
}

fn invalid(field: &str, message: &str) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_field",
        message,
        Some(field),
    )
}

fn no_control_plane() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_control_plane",
        "no control plane",
        None,
    )
}

fn not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "export_not_found",
        "export not found",
        None,
    )
}

fn unavailable(what: &str) -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unavailable",
        &format!("failed to {what} — nothing was changed"),
        None,
    )
}

async fn authenticate(headers: &HeaderMap) -> Result<Claims, Response> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
            None,
        ));
    }
    crate::auth::validate_authorization(auth)
        .await
        .map_err(|e| {
            let (status, message) = crate::auth::failure(&e);
            error(status, crate::auth::failure_code(&e), message, None)
        })
}

/// The write gate: authenticate, then capability + allowlist + SSO (OG-34/36), returning the
/// claims and the OG-35 actor.
async fn writer(
    headers: &HeaderMap,
) -> Result<(Claims, crate::db::control_audit::Actor), Response> {
    let claims = authenticate(headers).await?;
    let control = crate::control_plane::require_control(&claims, Capability::EditPolicies, headers)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((claims, control.audit))
}

/// What the plan grants this workspace. `None` = refused (fail-CLOSED): the plan does not
/// include span export, or there is no entitlement read at all.
async fn plan_max_exports(state: &AppState, claims: &Claims) -> Option<usize> {
    let cache = state.entitlements.as_ref()?;
    let e = cache.resolved(*claims.tenant_id.as_uuid()).await;
    e.f_otel_export
        .then(|| usize::try_from(e.max_exports).unwrap_or(usize::MAX))
}

fn not_entitled() -> Response {
    error(
        StatusCode::FORBIDDEN,
        "otel_export_required",
        "OTLP span export is not part of this workspace's plan",
        None,
    )
}

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
        Box::new(error(
            StatusCode::BAD_REQUEST,
            "invalid_field",
            // serde's message names a field or a type, never a value from the body's headers map.
            &format!(
                "the body must be a JSON object of the export fields: {}",
                first_line(&e.to_string())
            ),
            None,
        ))
    })
}

fn first_line(s: &str) -> String {
    s.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(160)
        .collect()
}

/// One export as the API shows it. The URL is host + path; header NAMES only; the live
/// in-process counters (fresher than the flushed row) when the directory holds the export.
pub(crate) fn view(e: &Export, tenant: Uuid) -> Value {
    let live = runtime::live(tenant, e.id);
    let (status, delivered, dropped, failed, depth, err) = match &live {
        Some(l) => (
            l.status.to_owned(),
            i64::try_from(l.delivered).unwrap_or(i64::MAX),
            i64::try_from(l.dropped).unwrap_or(i64::MAX),
            i64::try_from(l.failed).unwrap_or(i64::MAX),
            l.queue_depth,
            l.last_error_class
                .clone()
                .or_else(|| e.last_error_class.clone()),
        ),
        None => (
            e.status.clone(),
            e.delivered,
            e.dropped,
            e.failed,
            None,
            e.last_error_class.clone(),
        ),
    };
    json!({
        "id": e.id.to_string(),
        "name": e.name,
        "url": store::redacted_url(&e.url),
        "header_names": e.header_names,
        "enabled": e.enabled,
        "include_content": e.include_content,
        "sample_ratio": e.sample_ratio,
        "only_errors": e.only_errors,
        "status": status,
        "last_success_at": e.last_success_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        "last_error_class": err,
        // Honest delivery: in memory, at-most-once with bounded retry, lost on a restart.
        "delivery": "best_effort",
        "counters_since": "gateway_start",
        "delivered": delivered,
        "dropped": dropped,
        "failed": failed,
        "queue_depth": depth,
        "created_at": e.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "updated_at": e.updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

fn ok(body: Value) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(body),
    )
        .into_response()
}

// ── GET ──────────────────────────────────────────────────────────────────────────────────

async fn list_exports(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !claims.can(Capability::ViewPolicies) {
        return (
            StatusCode::FORBIDDEN,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            crate::auth::role_forbidden_json(Capability::ViewPolicies.least_role()),
        )
            .into_response();
    }
    let Some(pool) = state.pg.as_ref() else {
        return no_control_plane();
    };
    let list = match store::list(pool, &claims.tenant_id).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), tenant_id = %claims.tenant_id, "otel exports read failed");
            return unavailable("read the exports");
        }
    };
    let plan = plan_max_exports(&state, &claims).await;
    ok(json!({
        "exports": list.iter().map(|e| view(e, *claims.tenant_id.as_uuid())).collect::<Vec<_>>(),
        "plan": { "export_enabled": plan.is_some(), "max_exports": plan },
        "delivery": "best_effort",
    }))
}

// ── POST ─────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    name: String,
    url: String,
    #[serde(default)]
    headers: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    include_content: Option<bool>,
    #[serde(default)]
    sample_ratio: Option<f64>,
    #[serde(default)]
    only_errors: Option<bool>,
}

fn valid_name(raw: &str) -> Option<String> {
    let n = raw.trim();
    (!n.is_empty() && n.chars().count() <= 128 && !n.chars().any(char::is_control))
        .then(|| n.to_owned())
}

fn valid_ratio(r: f64) -> bool {
    r.is_finite() && (0.0..=1.0).contains(&r)
}

fn url_refusal(r: runtime::UrlRefusal) -> Response {
    match r {
        runtime::UrlRefusal::Invalid(m) => {
            error(StatusCode::BAD_REQUEST, "invalid_url", m, Some("url"))
        }
        runtime::UrlRefusal::SsrfBlocked => error(
            StatusCode::BAD_REQUEST,
            "ssrf_blocked",
            "the URL is not allowed (a private, loopback, link-local or metadata address)",
            Some("url"),
        ),
    }
}

async fn create_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (claims, actor) = match writer(&headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return no_control_plane();
    };
    let Some(max) = plan_max_exports(&state, &claims).await else {
        return not_entitled();
    };
    let body: CreateBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let Some(name) = valid_name(&body.name) else {
        return invalid("name", "name must be 1-128 characters");
    };
    let ratio = body.sample_ratio.unwrap_or(1.0);
    if !valid_ratio(ratio) {
        return invalid("sample_ratio", "sample_ratio must be between 0 and 1");
    }
    let hdrs = match body.headers.as_ref().map(runtime::validate_headers) {
        None => Vec::new(),
        Some(Ok(h)) => h,
        Some(Err((field, message))) => return invalid(&field, &message),
    };
    // The SSRF guard at CREATE (and again on every delivery).
    let url = match runtime::validate_url(&body.url).await {
        Ok(u) => u,
        Err(r) => return url_refusal(r),
    };
    let id = Uuid::new_v4();
    let tenant = *claims.tenant_id.as_uuid();
    let headers_enc = if hdrs.is_empty() {
        None
    } else {
        let Some(key) = crate::byok::master_key() else {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "encryption_unavailable",
                "this gateway has no BYOK master key, so it cannot store export headers — they \
                 are never stored in clear",
                None,
            );
        };
        match runtime::seal_headers(key, tenant, id, &hdrs) {
            Ok(enc) => enc,
            Err(_) => return unavailable("create the export"),
        }
    };
    let new = NewExport {
        id,
        name,
        url,
        headers_enc,
        header_names: hdrs.iter().map(|(n, _)| n.clone()).collect(),
        include_content: body.include_content.unwrap_or(false),
        sample_ratio: ratio,
        only_errors: body.only_errors.unwrap_or(false),
    };
    match crate::db::control_audit::scoped(
        actor,
        store::create(pool, &claims.tenant_id, &new, max, &claims.sub),
    )
    .await
    {
        Ok(CreateOutcome::Created(e)) => {
            runtime::refresh_now();
            let mut r = (StatusCode::CREATED, Json(view(&e, tenant))).into_response();
            r.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            r
        }
        Ok(CreateOutcome::LimitReached { max }) => (
            StatusCode::CONFLICT,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "error": "export_limit",
                "message": format!("this workspace already has {max} exports — delete one first"),
                "max": max,
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), tenant_id = %claims.tenant_id, "otel export create failed");
            unavailable("create the export")
        }
    }
}

// ── PATCH ────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchBody {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    include_content: Option<bool>,
    #[serde(default)]
    sample_ratio: Option<f64>,
    #[serde(default)]
    only_errors: Option<bool>,
    /// A map replaces the headers; `null` clears them.
    #[serde(default, deserialize_with = "crate::key_routes::present")]
    headers: Option<Option<serde_json::Map<String, Value>>>,
}

async fn update_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let (claims, actor) = match writer(&headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return no_control_plane();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return not_found();
    };
    if plan_max_exports(&state, &claims).await.is_none() {
        return not_entitled();
    }
    let body: PatchBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    if let Some(r) = body.sample_ratio
        && !valid_ratio(r)
    {
        return invalid("sample_ratio", "sample_ratio must be between 0 and 1");
    }
    let tenant = *claims.tenant_id.as_uuid();
    let headers_patch = match body.headers {
        None => None,
        Some(None) => Some((None, Vec::new())),
        Some(Some(map)) => {
            let hdrs = match runtime::validate_headers(&map) {
                Ok(h) => h,
                Err((field, message)) => return invalid(&field, &message),
            };
            if hdrs.is_empty() {
                Some((None, Vec::new()))
            } else {
                let Some(key) = crate::byok::master_key() else {
                    return error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "encryption_unavailable",
                        "this gateway has no BYOK master key, so it cannot store export headers",
                        None,
                    );
                };
                match runtime::seal_headers(key, tenant, id, &hdrs) {
                    Ok(enc) => Some((enc, hdrs.iter().map(|(n, _)| n.clone()).collect())),
                    Err(_) => return unavailable("update the export"),
                }
            }
        }
    };
    let patch = Patch {
        enabled: body.enabled,
        include_content: body.include_content,
        sample_ratio: body.sample_ratio,
        only_errors: body.only_errors,
        headers: headers_patch,
    };
    match crate::db::control_audit::scoped(
        actor,
        store::update(pool, &claims.tenant_id, id, &patch, &claims.sub),
    )
    .await
    {
        Ok(Some(e)) => {
            runtime::refresh_now();
            ok(view(&e, tenant))
        }
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), tenant_id = %claims.tenant_id, "otel export update failed");
            unavailable("update the export")
        }
    }
}

// ── DELETE ───────────────────────────────────────────────────────────────────────────────

async fn delete_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (claims, actor) = match writer(&headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return no_control_plane();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return not_found();
    };
    match crate::db::control_audit::scoped(
        actor,
        store::delete(pool, &claims.tenant_id, id, &claims.sub),
    )
    .await
    {
        Ok(true) => {
            runtime::refresh_now();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), tenant_id = %claims.tenant_id, "otel export delete failed");
            unavailable("delete the export")
        }
    }
}

// ── POST …/test ──────────────────────────────────────────────────────────────────────────

async fn test_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (claims, _actor) = match writer(&headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return no_control_plane();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return not_found();
    };
    if plan_max_exports(&state, &claims).await.is_none() {
        return not_entitled();
    }
    // A test is a real outbound request to the customer's host: its own per-workspace bucket,
    // so the admin plane cannot be used to hammer a receiver.
    if let Err(r) = crate::control_plane::charge_channel_test(&claims.tenant_id) {
        return r.into_response();
    }
    let sealed = match store::get_sealed(pool, &claims.tenant_id, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), tenant_id = %claims.tenant_id, "otel export read failed");
            return unavailable("read the export");
        }
    };
    let r = runtime::test_delivery(
        sealed.tenant_id,
        sealed.id,
        &sealed.url,
        sealed.headers_enc.as_deref(),
    )
    .await;
    // `200` either way: the endpoint worked, the DELIVERY is what the body reports.
    ok(json!({ "ok": r.ok, "class": r.class, "latency_ms": r.latency_ms }))
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, Role};

    fn claims(method: AuthMethod, role: Option<Role>) -> Claims {
        Claims {
            role,
            ..crate::auth::dev_stub_claims(method)
        }
    }

    #[test]
    fn og50_only_an_admin_manages_exports_a_developer_viewer_and_key_never_do() {
        for (who, c, write, read) in [
            (
                "admin",
                claims(AuthMethod::JwtBearer, Some(Role::Owner)),
                true,
                true,
            ),
            (
                "developer",
                claims(AuthMethod::JwtBearer, Some(Role::Member)),
                false,
                false,
            ),
            (
                "viewer",
                claims(AuthMethod::JwtBearer, Some(Role::Viewer)),
                false,
                false,
            ),
            (
                "billing",
                claims(AuthMethod::JwtBearer, Some(Role::Billing)),
                false,
                false,
            ),
            (
                "unrecognised",
                claims(AuthMethod::JwtBearer, None),
                false,
                false,
            ),
            ("api key", claims(AuthMethod::ApiKey, None), false, false),
            ("mtls", claims(AuthMethod::Mtls, None), false, false),
        ] {
            assert_eq!(c.can(Capability::EditPolicies), write, "{who} writes");
            assert_eq!(c.can(Capability::ViewPolicies), read, "{who} reads");
        }
    }

    #[test]
    fn og50_names_and_ratios_are_bounded() {
        assert_eq!(
            valid_name("  prod collector ").as_deref(),
            Some("prod collector")
        );
        assert_eq!(valid_name(""), None);
        assert_eq!(valid_name("a\nb"), None);
        assert_eq!(valid_name(&"x".repeat(129)), None);
        assert!(valid_ratio(0.0) && valid_ratio(1.0) && valid_ratio(0.25));
        for bad in [-0.1, 1.1, f64::NAN, f64::INFINITY] {
            assert!(!valid_ratio(bad), "{bad}");
        }
    }

    #[test]
    fn og50_a_url_is_refused_unless_https_with_a_host_and_a_traces_path() {
        for ok in [
            "https://otel.example.com/v1/traces",
            "https://collector.example.com:4318/v1/traces",
            "https://example.com/otlp/v1/traces",
        ] {
            assert!(runtime::check_url_syntax(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://otel.example.com/v1/traces",
            "https://otel.example.com/v1/metrics",
            "https://otel.example.com/",
            "https://user:pw@otel.example.com/v1/traces",
            "https://otel.example.com/v1/traces#frag",
            "ftp://otel.example.com/v1/traces",
            "not a url",
            "",
        ] {
            assert!(runtime::check_url_syntax(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn og50_the_view_never_carries_a_header_value_or_a_url_query() {
        let e = Export {
            id: Uuid::new_v4(),
            name: "prod".into(),
            url: "https://c.example.com/v1/traces?token=SUPERSECRET".into(),
            header_names: vec!["authorization".into(), "x-scope-orgid".into()],
            enabled: true,
            include_content: false,
            sample_ratio: 0.5,
            only_errors: false,
            status: "ok".into(),
            last_success_at: None,
            last_error_class: Some("http_503".into()),
            delivered: 1,
            dropped: 2,
            failed: 3,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let v = view(&e, Uuid::new_v4());
        let text = v.to_string();
        assert!(
            !text.contains("SUPERSECRET") && !text.contains("token="),
            "{text}"
        );
        assert_eq!(v["url"], "https://c.example.com/v1/traces");
        assert_eq!(v["delivery"], "best_effort");
        assert_eq!(v["counters_since"], "gateway_start");
        assert_eq!(v["header_names"], json!(["authorization", "x-scope-orgid"]));
        assert_eq!(v["dropped"], 2);
    }

    #[test]
    fn og50_a_patch_body_rejects_unknown_fields_and_distinguishes_null_from_absent() {
        // A smuggled tenant id (or a `url` change) is a 400, never read.
        assert!(serde_json::from_value::<PatchBody>(json!({"tenant_id":"x"})).is_err());
        assert!(serde_json::from_value::<PatchBody>(json!({"url":"https://x/v1/traces"})).is_err());
        let absent: PatchBody = serde_json::from_value(json!({"enabled": false})).unwrap();
        assert!(absent.headers.is_none());
        let cleared: PatchBody = serde_json::from_value(json!({"headers": null})).unwrap();
        assert!(matches!(cleared.headers, Some(None)));
        let set: PatchBody = serde_json::from_value(json!({"headers": {"a":"b"}})).unwrap();
        assert!(matches!(set.headers, Some(Some(_))));
        assert!(
            serde_json::from_value::<CreateBody>(json!({"name":"n","url":"u","tenant_id":"x"}))
                .is_err()
        );
    }
}
