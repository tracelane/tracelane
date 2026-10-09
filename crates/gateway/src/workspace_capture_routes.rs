//! GWY-53 — `/v1/workspace/capture`: a workspace owner chooses whether the gateway
//! records the workspace's prompt (input) and response (output) text
//! (`specs/GWY-53-self-serve-content-capture.md` §2.4).
//!
//! - `GET /v1/workspace/capture` → the stored choice, what the gateway applies, the
//!   retention window and the per-field cap. Any workspace role on a JWT, or the
//!   self-host master key; an API key is refused (a settings surface, not a data API).
//! - `PUT /v1/workspace/capture` `{input, output}` → verified OWNER JWT only.
//!
//! Every change is written to the tamper-evident ledger (`workspace.content_capture.set`)
//! inside the same Postgres transaction as the row (`db::workspace_capture::set_recorded`):
//! a ledger refusal rolls the change back and answers `503 audit_unavailable`, so a
//! customer can always prove from the ledger when capture was on. After a change this
//! process's entitlement entry is invalidated (the next request re-resolves inline);
//! another process sees it on its refresh.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use tracelane_shared::TenantId;

use crate::audit::AuditEvent;
use crate::auth::Claims;
use crate::db::workspace_capture::{self as store, SetError, WorkspaceCapture};
use crate::server::AppState;

/// The ledger event type for a change. A stable string: a verifier filters on it.
pub const LEDGER_EVENT: &str = "workspace.content_capture.set";

/// Mounted only when a Postgres control plane exists (`server.rs`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/workspace/capture", get(get_capture).put(put_capture))
        .with_state(state)
}

/// What a verb needs. Pure, so the role matrix is tested without a JWT issuer.
#[derive(Debug, Clone, Copy)]
enum Need {
    Read,
    Write,
}

/// The authorization decision — the ONE place it is made.
fn allowed(need: Need, claims: &Claims) -> bool {
    match need {
        // Any recognised workspace role, or the operator's master key (`can_admin`
        // is true for it and for an owner). An API key carries `role: None` and is
        // not admin since PL-9b, so it is refused; so is a JWT whose role slug was
        // absent or unrecognised (PL-9).
        Need::Read => claims.role.is_some() || claims.can_admin(),
        // A JWT, and an owner's: an API key never writes (a member can mint one), and
        // the master key is admin but not an owner's JWT.
        Need::Write => claims.is_verified_owner(),
    }
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}

async fn authorize(headers: &HeaderMap, need: Need) -> Result<Claims, Response> {
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
        .map_err(|_| {
            error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid credential",
            )
        })?;
    if !allowed(need, &claims) {
        let role = match need {
            Need::Read => "viewer",
            Need::Write => "owner",
        };
        return Err((
            StatusCode::FORBIDDEN,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            crate::auth::role_forbidden_json(role),
        )
            .into_response());
    }
    Ok(claims)
}

/// The ledger payload: the new value and the one it replaced, nothing else — no text,
/// no identifiers beyond what the event row already carries.
fn ledger_payload(previous: WorkspaceCapture, current: WorkspaceCapture) -> serde_json::Value {
    json!({
        "input": current.input,
        "output": current.output,
        "previous": { "input": previous.input, "output": previous.output },
    })
}

/// The GET/PUT body. `stored` is the workspace's own row; the rest is read through
/// the SAME paths the hot path uses (`capture_decision`, the entitlement cache).
async fn view(
    state: &AppState,
    claims: &Claims,
    stored: store::StoredCapture,
) -> serde_json::Value {
    let tenant: &TenantId = &claims.tenant_id;
    let cache = state.entitlements.as_deref();
    let effective = crate::server::config::content_capture_for(cache, tenant).await;
    // `queryable_days` is the window the retention sweep deletes at; `null` without a
    // control plane (the UI then states no number rather than a guessed one).
    let queryable_days = match cache {
        Some(c) => Some(c.resolved(*tenant.as_uuid()).await.queryable_days),
        None => None,
    };
    let operator_allowlisted =
        crate::server::config::trace_content().is_some_and(|c| c.captures(tenant));
    json!({
        "input": stored.setting.input,
        "output": stored.setting.output,
        "operator_allowlisted": operator_allowlisted,
        "effective": { "input": effective.input, "output": effective.output },
        "queryable_days": queryable_days,
        "max_field_bytes": effective.max_field_bytes,
        "updated_at": stored
            .updated_at
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        "can_edit": allowed(Need::Write, claims),
    })
}

async fn get_capture(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match authorize(&headers, Need::Read).await {
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
    let stored = match store::get(pool, &claims.tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "content capture read failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "read_failed",
                "could not read the content capture setting",
            );
        }
    };
    Json(view(&state, &claims, stored).await).into_response()
}

/// Both fields required; an unknown field (a smuggled `tenant_id`) is a `400`, never read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    input: bool,
    output: bool,
}

async fn put_capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PutBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let claims = match authorize(&headers, Need::Write).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // OG-36: the admin-plane gate (allowlist, SSO-required) → the OG-35 actor.
    let control = match crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::EditPolicies,
        &headers,
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    let Ok(Json(body)) = body else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "expected {\"input\": true|false, \"output\": true|false}",
        );
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    let new = WorkspaceCapture {
        input: body.input,
        output: body.output,
    };
    let chain = state.audit_chain.clone();
    let tenant = claims.tenant_id.clone();
    let actor = claims.sub.clone();
    // Fail-CLOSED (security path, CLAUDE.md §10): `publish` is the ledger's acked entry;
    // an `Err` here rolls the row back inside `set_recorded`.
    let record = move |previous: WorkspaceCapture| async move {
        chain
            .publish(AuditEvent {
                tenant_id: tenant,
                event_type: LEDGER_EVENT,
                actor,
                payload: ledger_payload(previous, new),
            })
            .await
    };
    let outcome = match store::set_recorded(pool, &claims.tenant_id, new, &control.audit, record)
        .await
    {
        Ok(o) => o,
        Err(SetError::Ledger(e)) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "content capture change refused: the ledger did not record it — nothing changed");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "not saved — the change could not be recorded in the audit ledger; try again",
            );
        }
        Err(SetError::Store(e)) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "content capture write failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save the content capture setting",
            );
        }
    };
    if outcome.changed
        && let Some(cache) = state.entitlements.as_ref()
    {
        cache.invalidate(*claims.tenant_id.as_uuid()).await;
    }
    let stored = store::StoredCapture {
        setting: outcome.current,
        updated_at: outcome.updated_at,
    };
    let mut body = view(&state, &claims, stored).await;
    body["changed"] = json!(outcome.changed);
    Json(body).into_response()
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

    /// Spec §7 row 4 — only a verified OWNER JWT may change capture. Loosening the
    /// write gate to `can_admin()` goes RED on the master key; loosening it to "any
    /// role" goes RED on member and viewer. Reads: any JWT role, never an API key.
    #[test]
    fn gwy53_only_a_verified_owner_jwt_may_write_any_role_may_read() {
        let owner = claims(AuthMethod::JwtBearer, Some(Role::Owner));
        let member = claims(AuthMethod::JwtBearer, Some(Role::Member));
        let viewer = claims(AuthMethod::JwtBearer, Some(Role::Viewer));
        let no_role_jwt = claims(AuthMethod::JwtBearer, None);
        let api_key = claims(AuthMethod::ApiKey, None);
        let master_key = claims(AuthMethod::SelfHostMasterKey, None);

        assert!(allowed(Need::Write, &owner));
        for (who, c) in [
            ("member", &member),
            ("viewer", &viewer),
            ("api key", &api_key),
            ("master key", &master_key),
            ("JWT with no recognised role", &no_role_jwt),
        ] {
            assert!(!allowed(Need::Write, c), "a {who} must not change capture");
        }

        for c in [&owner, &member, &viewer, &master_key] {
            assert!(allowed(Need::Read, c));
        }
        assert!(
            !allowed(Need::Read, &api_key),
            "an API key reads no settings"
        );
        assert!(
            !allowed(Need::Read, &no_role_jwt),
            "PL-9: an absent role slug on a JWT is a denial"
        );
    }

    #[test]
    fn gwy53_ledger_payload_carries_the_change_and_nothing_else() {
        let p = ledger_payload(
            WorkspaceCapture::default(),
            WorkspaceCapture {
                input: true,
                output: false,
            },
        );
        assert_eq!(
            p,
            json!({"input": true, "output": false, "previous": {"input": false, "output": false}})
        );
    }

    #[test]
    fn gwy53_body_refuses_a_missing_field_and_a_smuggled_tenant() {
        assert!(serde_json::from_str::<PutBody>(r#"{"input":true,"output":false}"#).is_ok());
        assert!(serde_json::from_str::<PutBody>(r#"{"input":true}"#).is_err());
        assert!(serde_json::from_str::<PutBody>(r#"{"input":"yes","output":false}"#).is_err());
        assert!(
            serde_json::from_str::<PutBody>(
                r#"{"input":true,"output":true,"tenant_id":"00000000-0000-0000-0000-000000000002"}"#
            )
            .is_err(),
            "a tenant in the body is refused, never read"
        );
    }

    /// Without a control plane there is nothing to store: an owner's PUT is a clean
    /// 503 after the auth gate, never a silent success.
    #[tokio::test]
    async fn gwy53_no_control_plane_is_a_503_not_a_silent_success() {
        let state = crate::handler_harness::test_state(
            crate::providers::ProviderRegistry::new().expect("registry"),
        );
        let resp = put_capture(
            State(state.clone()),
            crate::handler_harness::authed(),
            Ok(Json(PutBody {
                input: true,
                output: true,
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let resp = get_capture(State(state), crate::handler_harness::authed()).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Spec §7 row 6, through the REAL handler against a REAL Postgres: an owner's
    /// change appends exactly ONE ledger event, a no-op appends none, the GET reflects
    /// the new effective decision immediately (cache invalidated), and a ledger that
    /// refuses leaves the setting unchanged with `503 audit_unavailable`.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn gwy53_put_records_the_change_on_the_ledger_against_real_postgres() {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let mut cfg = deadpool_postgres::Config::new();
        cfg.url = Some(url);
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .expect("pool");
        let tenant = crate::handler_harness::dev_tenant();
        let id = *tenant.as_uuid();
        {
            let client = pool.get().await.expect("connect");
            client
                .execute("DELETE FROM tenants WHERE id = $1", &[&id])
                .await
                .expect("clean slate");
            // The migrations seed no `plan_entitlements` rows; without one the
            // resolver falls to `deny_all` and `effective` could never turn on.
            client
                .execute(
                    "INSERT INTO plan_entitlements (plan_lookup_key, indexed_window_days, queryable_days, ledger_days) \
                 VALUES ('builder_v1', 30, 730, 730) \
                     ON CONFLICT (plan_lookup_key) DO NOTHING",
                    &[],
                )
                .await
                .expect("plan row");
            client
                .execute(
                    // `builder`: a plan the migrations seed, so the entitlement
                    // resolver matches instead of falling to `deny_all`.
                    "INSERT INTO tenants (id, workos_org_id, name, plan) \
                     VALUES ($1, $2, 'gwy53-dev', 'builder'::text::plan)",
                    &[
                        &id,
                        &format!("org_gwy53_dev_{}", uuid::Uuid::new_v4().simple()),
                    ],
                )
                .await
                .expect("dev tenant");
        }
        let chain = crate::handler_harness::in_memory_chain();
        let mut state = crate::handler_harness::test_state_with_chain(
            crate::providers::ProviderRegistry::new().expect("registry"),
            chain.clone(),
        );
        state.pg = Some(pool.clone());
        state.entitlements = Some(std::sync::Arc::new(
            crate::entitlement_cache::EntitlementCache::new(crate::entitlement_cache::pg_resolver(
                pool.clone(),
            )),
        ));
        let put = |state: AppState, input: bool, output: bool| async move {
            put_capture(
                State(state),
                crate::handler_harness::authed(),
                Ok(Json(PutBody { input, output })),
            )
            .await
        };

        // Warm the cache with the OFF value, so the GET after the PUT proves the
        // invalidation rather than a first resolve.
        let before = crate::handler_harness::body_json(
            get_capture(State(state.clone()), crate::handler_harness::authed()).await,
        )
        .await;
        assert_eq!(
            before["effective"],
            json!({"input": false, "output": false})
        );
        assert_eq!(before["updated_at"], serde_json::Value::Null);
        let seq0 = chain.in_memory_seq(&tenant);

        let resp = put(state.clone(), true, true).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = crate::handler_harness::body_json(resp).await;
        assert_eq!(body["changed"], json!(true));
        assert_eq!(body["effective"], json!({"input": true, "output": true}));
        assert!(
            body["updated_at"]
                .as_str()
                .is_some_and(|s| s.ends_with('Z'))
        );
        assert!(
            body["queryable_days"].as_i64().is_some_and(|d| d > 0),
            "the window the toggle states comes from the plan: {body}"
        );
        assert_eq!(
            chain.in_memory_seq(&tenant),
            seq0 + 1,
            "a change appends exactly one ledger event"
        );

        let resp = put(state.clone(), true, true).await;
        let body = crate::handler_harness::body_json(resp).await;
        assert_eq!(body["changed"], json!(false));
        assert_eq!(
            chain.in_memory_seq(&tenant),
            seq0 + 1,
            "a no-op appends nothing"
        );

        // A ledger that refuses: nothing changes.
        let mut refusing = state.clone();
        refusing.audit_chain = crate::handler_harness::unreachable_pg_chain();
        let resp = put(refusing, false, false).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            crate::handler_harness::body_json(resp).await["error"],
            json!("audit_unavailable")
        );
        let after = store::get(&pool, &tenant).await.expect("read");
        assert_eq!(
            after.setting,
            WorkspaceCapture {
                input: true,
                output: true
            },
            "a change the ledger refused must not land"
        );

        let client = pool.get().await.expect("connect");
        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .expect("cleanup");
    }
}
