//! `OG-51` — `/v1/cache`: the workspace's own response-cache controls
//! (`specs/OG-51-cache-controls.md` §2).
//!
//! | Route | Who | Audit |
//! |---|---|---|
//! | `GET /v1/cache` — the effective settings with the SOURCE of each value, the epochs, the operator on/off, 24 h hits and cost saved | capability `view_settings` (every workspace role but an unrecognised slug; never an API key) | — |
//! | `PUT /v1/cache/settings` `{mode, ttl_hours, namespace_by, semantic}` | capability `edit_policies` (admin) | `cache.settings.set` |
//! | `POST /v1/cache/invalidate` `{scope}` | capability `edit_policies` (admin) | `cache.invalidate` |
//!
//! Registered in `CONTROL_ROUTES` (`auth/capability.rs`); every write goes through
//! `control_plane::require_control` (capability, admin IP allowlist, SSO-required) and
//! records ONE `admin_audit_log` row in the change's own transaction (fail-CLOSED).
//! Mounted only with a Postgres control plane; the tenant is `claims.tenant_id` ONLY.
//!
//! **Invalidation is a generation counter, not a delete** — the gateway's ClickHouse user
//! holds no delete grant. The response says `"effect": "stop_serving"`; it never claims
//! erasure (the old rows age out by TTL, capacity and the retention sweeper).

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracelane_shared::TenantId;

use crate::auth::Claims;
use crate::auth::capability::Capability;
use crate::cache_controls as cc;
use crate::db::cache_settings::{self as store, BumpOutcome, Mode, NamespaceBy, Settings};
use crate::server::AppState;

/// Mounted only when a Postgres control plane exists (`server.rs`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/cache", get(get_cache))
        .route("/v1/cache/settings", put(put_settings))
        .route("/v1/cache/invalidate", post(invalidate))
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

fn no_control_plane() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_control_plane",
        "no control plane",
        None,
    )
}

/// Does the PLAN grant response-cache control (`on`, a workspace TTL)? Fail-CLOSED
/// (`.claude/rules/tenancy.md`): no entitlement read = no control plane = refused.
fn plan_grants(e: Option<&crate::entitlement_cache::ResolvedEntitlements>) -> bool {
    e.is_some_and(|e| e.f_cache_control && e.cache_ttl_hours > 0)
}

// ── GET /v1/cache ────────────────────────────────────────────────────────────

/// Where a value came from, for the "source of each value" the spec asks for.
fn source(is_set: bool) -> &'static str {
    if is_set { "workspace" } else { "default" }
}

/// The GET/PUT body. Pure over what the entitlement cache holds, so it is unit-testable.
pub(crate) fn view(
    claims: &Claims,
    operator: Option<(u32, f32)>,
    e: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    capture: crate::server::config::ContentCapture,
) -> Value {
    let loaded = e.map(|e| &*e.cache);
    let ws = loaded.map(|l| l.settings).unwrap_or_default();
    let plan = e
        .filter(|e| e.f_cache_control && e.cache_ttl_hours > 0)
        .map(|e| e.cache_ttl_hours);
    let state = cc::enabled(
        operator.is_some(),
        loaded,
        None,
        plan.is_some(),
        capture.judge_may_read(),
    );
    let cfg = cc::config();
    let operator_ttl = operator.map(|(t, _)| t);
    let ttl_floor = [ws.ttl_hours.filter(|_| plan.is_some()), plan, operator_ttl]
        .into_iter()
        .flatten()
        .min();
    let effective_ttl = ttl_floor.map(|t| t.min(cfg.ttl_ceiling_hours));
    let ttl_source = match (effective_ttl, ttl_floor) {
        (Some(eff), Some(floor)) if eff < floor => "ceiling",
        (Some(eff), _) if ws.ttl_hours.is_some() && plan.is_some() && Some(eff) == ws.ttl_hours => {
            "workspace"
        }
        (Some(eff), _) if Some(eff) == plan => "plan",
        (Some(_), _) => "operator",
        (None, _) => "none",
    };
    let epochs: Vec<Value> = loaded
        .map(|l| {
            l.epochs
                .iter()
                .map(|(scope, epoch)| json!({ "scope": scope, "epoch": epoch }))
                .collect()
        })
        .unwrap_or_default();
    let keys: Vec<Value> = loaded
        .map(|l| {
            l.keys
                .iter()
                .map(|(id, k)| {
                    let mut v = k.to_json();
                    v["key_id"] = json!(id.to_string());
                    v
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "operator": {
            "enabled": operator.is_some(),
            "ttl_hours": operator_ttl,
            "similarity_threshold": operator.map(|(_, t)| t),
        },
        "plan": {
            "cache_control": plan.is_some(),
            "ttl_hours": plan,
        },
        "settings": {
            "mode": { "value": ws.mode.as_str(), "source": source(ws.mode != Mode::Inherit) },
            "ttl_hours": { "value": ws.ttl_hours, "source": source(ws.ttl_hours.is_some()) },
            "namespace_by": {
                "value": ws.namespace_by.as_str(),
                "source": source(ws.namespace_by != NamespaceBy::Workspace),
            },
            "semantic": { "value": ws.semantic, "source": source(!ws.semantic) },
            "updated_at": loaded
                .and_then(|l| l.updated_at)
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        },
        "effective": {
            "enabled": state.on,
            // A stable code: operator_cache_not_configured | key_cache_off |
            // workspace_cache_off | content_capture_off.
            "why_off": state.why_off,
            "inherit_requires_capture": cfg.inherit_requires_capture,
            "content_capture": { "input": capture.input, "output": capture.output },
            "ttl_hours": effective_ttl,
            "ttl_source": ttl_source,
            "ttl_ceiling_hours": cfg.ttl_ceiling_hours,
            "semantic": ws.semantic,
        },
        "epochs": epochs,
        "keys": keys,
        "can_edit": claims.can(Capability::EditPolicies),
    })
}

/// 24 h hits and cost saved from the tenant's spans. **A display path: fail-OPEN** — a read
/// failure is `null` with `stats_unavailable: true`, never a zero.
async fn stats(state: &AppState, tenant: &TenantId, window_hours: u32) -> Value {
    #[derive(Deserialize, clickhouse::Row)]
    struct StatRow {
        hits: u64,
        saved: f64,
    }
    let unavailable = || {
        json!({ "window_hours": window_hours, "hits": null, "cost_saved_usd": null,
                "stats_unavailable": true })
    };
    let Some(url) = state.quota_ch_url.clone() else {
        return unavailable();
    };
    let tier = crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), tenant).await;
    let sql = crate::clickhouse_query::TenantQuery::new(
        "SELECT toUInt64(countIf(hit)) AS hits, sumIf(saved, hit) AS saved FROM ( \
           SELECT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit') AS hit, \
                  JSONExtractFloat(attributes, 'tracelane_semantic_cache_cost_saved_usd') AS saved \
           FROM spans FINAL \
           WHERE tenant_id = ? AND start_time >= now() - toIntervalHour(?))",
        tier,
    )
    .with_log_comment(format!("tenant_id={tenant}"))
    .sql_with_settings();
    match crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(tenant.to_string())
        .bind(window_hours)
        .fetch_one::<StatRow>()
        .await
    {
        Ok(r) if r.saved.is_finite() => json!({
            "window_hours": window_hours,
            "hits": r.hits,
            "cost_saved_usd": r.saved,
            "stats_unavailable": false,
        }),
        Ok(_) | Err(_) => unavailable(),
    }
}

async fn get_cache(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // A settings surface, not a data API: a role holding `view_settings` (every workspace
    // role but an unrecognised slug) or the operator; an API key is refused.
    if !claims.can(Capability::ViewSettings) {
        return (
            StatusCode::FORBIDDEN,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            crate::auth::role_forbidden_json(Capability::ViewSettings.least_role()),
        )
            .into_response();
    }
    if state.pg.is_none() {
        return no_control_plane();
    }
    let Some(entitlements) = state.entitlements.as_ref() else {
        return no_control_plane();
    };
    let tenant = &claims.tenant_id;
    let resolved = entitlements.resolved(*tenant.as_uuid()).await;
    let capture = crate::server::config::content_capture_for(Some(entitlements), tenant).await;
    let operator = state
        .semantic_cache
        .as_ref()
        .map(|c| (c.config().ttl_hours(), c.config().default_threshold()));
    let mut body = view(&claims, operator, Some(&resolved), capture);
    body["stats"] = stats(&state, tenant, cc::config().stats_window_hours).await;
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(body),
    )
        .into_response()
}

// ── PUT /v1/cache/settings ───────────────────────────────────────────────────

/// A full document: an absent field is its default. An unknown field (a smuggled
/// `tenant_id`) is a `400`, never read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default, deserialize_with = "crate::key_routes::present")]
    ttl_hours: Option<Option<i64>>,
    #[serde(default)]
    namespace_by: Option<String>,
    #[serde(default)]
    semantic: Option<bool>,
}

/// Validate a settings document against the plan. Pure.
///
/// # Errors
/// The refusal response: `400 invalid_field`, or `403 cache_control_not_entitled` for `on`
/// or a workspace TTL without the plan's `f_cache_control` (fail-CLOSED: no entitlement
/// read at all refuses too).
fn validate(
    body: PutBody,
    e: Option<&crate::entitlement_cache::ResolvedEntitlements>,
) -> Result<Settings, Box<Response>> {
    let mode = match body.mode.as_deref() {
        None => Mode::Inherit,
        Some(m) => Mode::parse(m)
            .ok_or_else(|| Box::new(invalid("mode", "mode must be inherit, on or off")))?,
    };
    let namespace_by = match body.namespace_by.as_deref() {
        None => NamespaceBy::Workspace,
        Some(n) => NamespaceBy::parse(n).ok_or_else(|| {
            Box::new(invalid(
                "namespace_by",
                "namespace_by must be workspace, project, end_user or key",
            ))
        })?,
    };
    let ceiling = cc::config().ttl_ceiling_hours;
    let ttl_hours = match body.ttl_hours {
        None | Some(None) => None,
        Some(Some(t)) => {
            let t = u32::try_from(t)
                .ok()
                .filter(|t| (1..=ceiling).contains(t))
                .ok_or_else(|| {
                    Box::new(invalid(
                        "ttl_hours",
                        &format!("ttl_hours must be between 1 and {ceiling} (or null)"),
                    ))
                })?;
            Some(t)
        }
    };
    let settings = Settings {
        mode,
        ttl_hours,
        namespace_by,
        semantic: body.semantic.unwrap_or(true),
    };
    if (settings.mode == Mode::On || settings.ttl_hours.is_some()) && !plan_grants(e) {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "cache_control_not_entitled",
            "turning the response cache on, or setting its TTL, is not part of this workspace's \
             plan — `inherit`, `off` and the namespace do not need it",
            None,
        )));
    }
    Ok(settings)
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
            &format!("the body must be a JSON object of the cache settings: {e}"),
            None,
        ))
    })
}

async fn put_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // OG-34 capability, OG-36 allowlist + SSO-required → the OG-35 actor.
    let control =
        match crate::control_plane::require_control(&claims, Capability::EditPolicies, &headers)
            .await
        {
            Ok(a) => a,
            Err(r) => return r.into_response(),
        };
    let Some(pool) = state.pg.as_ref() else {
        return no_control_plane();
    };
    let parsed: PutBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    // The plan is read from the SAME warm cache the hot path reads (never Postgres here).
    let resolved = match state.entitlements.as_ref() {
        Some(c) => Some(c.resolved(*claims.tenant_id.as_uuid()).await),
        None => None,
    };
    let settings = match validate(parsed, resolved.as_deref()) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let outcome = match crate::db::control_audit::scoped(
        control.audit.clone(),
        store::set_settings(pool, &claims.tenant_id, &settings, &claims.sub),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), tenant_id = %claims.tenant_id, "cache settings write failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to save the cache settings — nothing was changed",
                None,
            );
        }
    };
    if outcome.changed
        && let Some(cache) = state.entitlements.as_ref()
    {
        cache.invalidate(*claims.tenant_id.as_uuid()).await;
    }
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "changed": outcome.changed,
            "previous": outcome.previous.to_json(),
            "settings": outcome.current.to_json(),
        })),
    )
        .into_response()
}

// ── POST /v1/cache/invalidate ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidateBody {
    scope: String,
}

/// A scope the invalidation API accepts: `workspace`, `project:<uuid>`, `key:<uuid>` or
/// `model:<name>`. The model name is the one the cache key hashes (the workspace-alias
/// TARGET), at most 128 characters of `[A-Za-z0-9._:/@+-]`.
pub(crate) fn parse_scope(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw == "workspace" {
        return Some(raw.to_owned());
    }
    let (kind, rest) = raw.split_once(':')?;
    match kind {
        "project" | "key" => uuid::Uuid::parse_str(rest)
            .ok()
            .map(|u| format!("{kind}:{u}")),
        "model" => {
            let ok = !rest.is_empty()
                && rest.len() <= 128
                && rest.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
                });
            ok.then(|| format!("model:{rest}"))
        }
        _ => None,
    }
}

async fn invalidate(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let control =
        match crate::control_plane::require_control(&claims, Capability::EditPolicies, &headers)
            .await
        {
            Ok(a) => a,
            Err(r) => return r.into_response(),
        };
    let Some(pool) = state.pg.as_ref() else {
        return no_control_plane();
    };
    let parsed: InvalidateBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let Some(scope) = parse_scope(&parsed.scope) else {
        return invalid(
            "scope",
            "scope must be `workspace`, `project:<uuid>`, `key:<uuid>` or `model:<name>`",
        );
    };
    let max = cc::config().max_epoch_rows_per_tenant;
    match crate::db::control_audit::scoped(
        control.audit.clone(),
        store::bump_epoch(pool, &claims.tenant_id, &scope, max, &claims.sub),
    )
    .await
    {
        Ok(BumpOutcome::Bumped { epoch }) => {
            if let Some(cache) = state.entitlements.as_ref() {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                Json(json!({
                    "scope": scope,
                    "epoch": epoch,
                    // The gateway cannot delete cached rows (no ClickHouse delete grant): the
                    // old entries stop being served on both tiers and age out by TTL,
                    // capacity and the retention sweeper. Never "erased".
                    "effect": "stop_serving",
                    "note": "cached answers for this scope are no longer served; stored rows age out by TTL",
                })),
            )
                .into_response()
        }
        Ok(BumpOutcome::LimitReached { max }) => error(
            StatusCode::CONFLICT,
            "epoch_limit",
            &format!(
                "this workspace already has {max} invalidation scopes — invalidate `workspace` instead"
            ),
            None,
        ),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), tenant_id = %claims.tenant_id, "cache invalidation failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to invalidate the cache — nothing was changed",
                None,
            )
        }
    }
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

    fn entitled() -> crate::entitlement_cache::ResolvedEntitlements {
        let mut e = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        e.f_cache_control = true;
        e.cache_ttl_hours = 720;
        e
    }

    fn body(v: Value) -> PutBody {
        serde_json::from_value(v).expect("body")
    }

    #[test]
    fn og51_scopes_are_a_closed_vocabulary() {
        let u = uuid::Uuid::new_v4();
        assert_eq!(parse_scope("workspace").as_deref(), Some("workspace"));
        assert_eq!(
            parse_scope(&format!("project:{u}")),
            Some(format!("project:{u}"))
        );
        assert_eq!(parse_scope(&format!(" key:{u} ")), Some(format!("key:{u}")));
        assert_eq!(parse_scope("model:gpt-4o").as_deref(), Some("model:gpt-4o"));
        for bad in [
            "",
            "all",
            "project:not-a-uuid",
            "key:",
            "model:",
            "model:has space",
            "tenant:abc",
            &format!("model:{}", "a".repeat(129)),
        ] {
            assert_eq!(parse_scope(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn og51_on_and_a_workspace_ttl_need_the_plan_and_fail_closed_without_a_cache() {
        let on = || body(json!({"mode":"on"}));
        let ttl = || body(json!({"ttl_hours": 24}));
        for (name, f) in [("on", on as fn() -> PutBody), ("ttl", ttl)] {
            let r = validate(
                f(),
                Some(&crate::entitlement_cache::ResolvedEntitlements::deny_all()),
            );
            assert_eq!(
                r.expect_err("refused").status(),
                StatusCode::FORBIDDEN,
                "{name} without the plan"
            );
            assert_eq!(
                validate(f(), None).expect_err("refused").status(),
                StatusCode::FORBIDDEN,
                "{name} with no entitlement read at all"
            );
            assert!(
                validate(f(), Some(&entitled())).is_ok(),
                "{name} with the plan"
            );
        }
        // `inherit`, `off` and a namespace never need the plan.
        for v in [
            json!({}),
            json!({"mode":"off"}),
            json!({"mode":"inherit","namespace_by":"key"}),
            json!({"semantic": false}),
        ] {
            assert!(validate(body(v), None).is_ok());
        }
    }

    #[test]
    fn og51_the_document_is_validated_field_by_field() {
        for (v, field) in [
            (json!({"mode":"always"}), "mode"),
            (json!({"namespace_by":"galaxy"}), "namespace_by"),
            (json!({"ttl_hours": 0}), "ttl_hours"),
            (json!({"ttl_hours": -5}), "ttl_hours"),
            (json!({"ttl_hours": 100000}), "ttl_hours"),
        ] {
            let r = *validate(body(v.clone()), Some(&entitled())).expect_err("refused");
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{v}");
            let _ = field;
        }
        // An unknown field is rejected by the type (a smuggled tenant id is never read).
        assert!(serde_json::from_value::<PutBody>(json!({"tenant_id":"x"})).is_err());
        // The default document is the default settings.
        assert_eq!(
            validate(body(json!({})), None).ok(),
            Some(Settings::default())
        );
        let s = validate(
            body(json!({"mode":"on","ttl_hours":24,"namespace_by":"end_user","semantic":false})),
            Some(&entitled()),
        )
        .expect("valid");
        assert_eq!(s.mode, Mode::On);
        assert_eq!(s.ttl_hours, Some(24));
        assert_eq!(s.namespace_by, NamespaceBy::EndUser);
        assert!(!s.semantic);
    }

    #[test]
    fn og51_the_view_names_the_source_and_the_reason_the_cache_is_off() {
        let owner = claims(AuthMethod::JwtBearer, Some(Role::Owner));
        let capture_off = crate::server::config::ContentCapture {
            input: false,
            output: false,
            max_field_bytes: 1,
        };
        let capture_on = crate::server::config::ContentCapture {
            input: true,
            output: true,
            max_field_bytes: 1,
        };
        let e = entitled();
        // The privacy default: operator block present, capture off, never opted in.
        let v = view(&owner, Some((168, 0.95)), Some(&e), capture_off);
        assert_eq!(v["effective"]["enabled"], false);
        assert_eq!(v["effective"]["why_off"], "content_capture_off");
        assert_eq!(v["settings"]["mode"]["source"], "default");
        assert_eq!(v["can_edit"], true);
        // Capture on: served.
        let v = view(&owner, Some((168, 0.95)), Some(&e), capture_on);
        assert_eq!(v["effective"]["enabled"], true);
        // No operator block: nothing to enable, said so.
        let v = view(&owner, None, Some(&e), capture_on);
        assert_eq!(v["effective"]["why_off"], "operator_cache_not_configured");
        // The ceiling binds a 720 h plan.
        let v = view(&owner, Some((720, 0.95)), Some(&e), capture_on);
        assert_eq!(v["effective"]["ttl_hours"], 168);
        assert_eq!(v["effective"]["ttl_source"], "ceiling");
        // A viewer reads it but cannot edit.
        let viewer = claims(AuthMethod::JwtBearer, Some(Role::Viewer));
        assert_eq!(view(&viewer, None, None, capture_off)["can_edit"], false);
    }

    #[test]
    fn og51_reads_need_view_settings_and_writes_edit_policies() {
        let allowed = |c: &Claims, cap| c.can(cap);
        for role in [Role::Owner, Role::Member, Role::Viewer, Role::Billing] {
            let c = claims(AuthMethod::JwtBearer, Some(role));
            assert!(allowed(&c, Capability::ViewSettings), "{role:?} reads");
            assert_eq!(
                allowed(&c, Capability::EditPolicies),
                role == Role::Owner,
                "{role:?} writes only as admin"
            );
        }
        let key = claims(AuthMethod::ApiKey, None);
        assert!(
            !key.can(Capability::ViewSettings),
            "an API key reads no settings"
        );
        assert!(
            !key.can(Capability::EditPolicies),
            "an API key never writes"
        );
        assert!(
            !claims(AuthMethod::JwtBearer, None).can(Capability::ViewSettings),
            "PL-9: an absent role slug is a denial"
        );
    }
}
