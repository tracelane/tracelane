//! Scoped rail policy control plane. Never accepts a tenant from input.
use super::{
    policy::{Policy, RAILS},
    policy_store,
    rail::{GuardrailFeature, RailGate},
};
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    scope: Option<String>,
    id: Option<Uuid>,
}
impl Scope {
    fn resolve(&self, tenant: Uuid) -> Option<(&str, Uuid)> {
        let scope = self.scope.as_deref().unwrap_or("workspace");
        match (scope, self.id) {
            ("workspace", None) => Some((scope, tenant)),
            ("key" | "project", Some(id)) => Some((scope, id)),
            _ => None,
        }
    }
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/guardrails/policy", get(read).put(write))
        .with_state(state)
}
fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({"error":code})),
    )
        .into_response()
}
async fn authorize(
    headers: &HeaderMap,
    capability: crate::auth::capability::Capability,
) -> Result<(crate::auth::Claims, crate::db::control_audit::Actor), Response> {
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let claims = crate::auth::validate_authorization(raw)
        .await
        .map_err(|e| {
            let (status, _) = crate::auth::failure(&e);
            error(status, crate::auth::failure_code(&e))
        })?;
    let control = crate::control_plane::require_control(&claims, capability, headers)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((claims, control.audit))
}

pub fn eligible(gate: &RailGate, name: &str) -> bool {
    let feature = match name {
        "R2_secrets_pii" => Some(GuardrailFeature::R2SecretsPii),
        "R5_format" => Some(GuardrailFeature::R5Format),
        "R6_sysprompt_leak" => Some(GuardrailFeature::R6SysPromptLeak),
        "R7_topic_competitor" => Some(GuardrailFeature::R7TopicCompetitor),
        _ => None,
    };
    gate.enables(feature)
}

fn default_behavior(name: &str) -> Value {
    match name {
        "R1_cost" => {
            let c = super::rails::r1_cost::R1Config::default();
            json!({"mode":"block", "thresholds":{
                "max_input_tokens":c.max_input_tokens,"max_output_tokens":c.max_output_tokens,
                "max_steps_per_run":c.max_steps_per_run,"max_identical_tool_calls":c.max_identical_tool_calls,
                "max_subagent_depth":c.max_subagent_depth}, "override_caps":"clamped_to_default"})
        }
        "R2_secrets_pii" => {
            json!({"mode":"redact","custom_limits":super::pii_policy::custom_limits()})
        }
        "R6_sysprompt_leak" => {
            json!({"mode":"redact","thresholds":{"min_tokens":super::rails::r6_sysprompt_leak::MIN_LEAK_TOKENS}})
        }
        "R5_format" | "R4_trifecta" => json!({"mode":"observe"}),
        "R8_injection" => {
            json!({"mode":"built_in","high_confidence":"block","medium_confidence":"observe"})
        }
        "R3_schema" => json!({"mode":"built_in","injection":"block","schema_invalid":"observe"}),
        "R3_pinning" => json!({"mode":"built_in","suspended":"block","definition_drift":"observe"}),
        "R7_topic_competitor" => {
            json!({"mode":"built_in","denied_topic":"block","competitor":"redact","configured_terms":false,
                "term_limits": super::policy::term_limits()})
        }
        _ => Value::Null,
    }
}

/// Fail-CLOSED on auth, ownership, or store failure.
#[tracing::instrument(skip_all)]
async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(scope): Query<Scope>,
) -> Response {
    let (claims, _) =
        match authorize(&headers, crate::auth::capability::Capability::ViewPolicies).await {
            Ok(c) => c,
            Err(e) => return e,
        };
    let tenant = claims.tenant_id.as_uuid();
    let Some((scope, id)) = scope.resolve(*tenant) else {
        return error(StatusCode::BAD_REQUEST, "invalid_scope");
    };
    let Some(pool) = &state.pg else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable");
    };
    let client = match pool.get().await {
        Ok(c) => c,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"),
    };
    match policy_store::owns(&**client, tenant, scope, &id).await {
        Ok(true) => (),
        Ok(false) => return error(StatusCode::NOT_FOUND, "scope_not_found"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"),
    }
    let snapshot = match policy_store::load(&client, tenant).await {
        Ok(p) => p,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"),
    };
    let stored = match scope {
        "key" => snapshot.keys.get(&id),
        "project" => snapshot.projects.get(&id),
        _ => snapshot.workspace.as_ref(),
    };
    let key = (scope == "key").then(|| id.to_string());
    let effective = snapshot.effective(
        key.as_deref(),
        if scope == "key" {
            snapshot.key_projects.get(&id).copied()
        } else {
            (scope == "project").then_some(id)
        },
    );
    let gate = RailGate::resolve(state.entitlements.as_deref(), *tenant).await;
    let rails: serde_json::Map<String, Value> = RAILS.iter().map(|name| ((*name).into(), json!({
        "entitled": eligible(&gate, name), "enabled": eligible(&gate, name) && effective.enabled(name),
        "override": effective.rails.get(*name), "default_behavior": default_behavior(name),
    }))).collect();
    let etag = policy_store::etag(stored);
    let mut response = (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({"scope":scope,"id":id,"policy":stored,"effective":rails,"etag":etag,"can_edit":claims.can(crate::auth::capability::Capability::EditPolicies)})),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

/// Fail-CLOSED: validation, ownership and audit must succeed before a policy is visible.
#[tracing::instrument(skip_all)]
async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(scope): Query<Scope>,
    Json(value): Json<Value>,
) -> Response {
    let (claims, actor) =
        match authorize(&headers, crate::auth::capability::Capability::EditPolicies).await {
            Ok(c) => c,
            Err(e) => return e,
        };
    let Some((scope, id)) = scope.resolve(*claims.tenant_id.as_uuid()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_scope");
    };
    let Some(expected_etag) = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with('"') && v.ends_with('"') && v.len() == 66)
    else {
        return error(StatusCode::PRECONDITION_REQUIRED, "if_match_required");
    };
    if !value.is_null() && Policy::parse(&value).is_none() {
        return error(StatusCode::BAD_REQUEST, "invalid_policy");
    }
    let Some(pool) = &state.pg else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable");
    };
    match policy_store::write(
        pool,
        &claims.tenant_id,
        scope,
        id,
        &value,
        expected_etag,
        &actor,
    )
    .await
    {
        Ok(policy_store::WriteOutcome::Updated) => {
            if let Some(cache) = &state.entitlements {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            let etag = policy_store::etag((!value.is_null()).then_some(&value));
            let mut response = (
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                Json(json!({"scope":scope,"id":id,"policy":value,"etag":etag})),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&etag) {
                response.headers_mut().insert(header::ETAG, value);
            }
            response
        }
        Ok(policy_store::WriteOutcome::NotFound) => error(StatusCode::NOT_FOUND, "scope_not_found"),
        Ok(policy_store::WriteOutcome::Conflict) => error(StatusCode::CONFLICT, "policy_conflict"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "policy_write_failed"),
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, Role};
    #[tokio::test]
    async fn og30_policy_api_requires_edit_policies_capability() {
        for role in [Role::Member, Role::Viewer, Role::Billing] {
            let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
            claims.role = Some(role);
            let _guard = crate::media_common::test_support::as_claims(claims);
            let response = match authorize(
                &crate::handler_harness::authed(),
                crate::auth::capability::Capability::EditPolicies,
            )
            .await
            {
                Err(response) => response,
                Ok(_) => panic!("role must be refused"),
            };
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
    #[tokio::test]
    async fn og62_viewer_cannot_get_or_put_policy() {
        let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
        claims.role = Some(Role::Viewer);
        let _guard = crate::media_common::test_support::as_claims(claims);
        let refused_read = authorize(
            &crate::handler_harness::authed(),
            crate::auth::capability::Capability::ViewPolicies,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(refused_read.status(), StatusCode::FORBIDDEN);
        let refused = authorize(
            &crate::handler_harness::authed(),
            crate::auth::capability::Capability::EditPolicies,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn og62_put_without_if_match_returns_428() {
        let claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
        let _guard = crate::media_common::test_support::as_claims(claims);
        let state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        let response = write(
            State(state),
            crate::handler_harness::authed(),
            Query(Scope::default()),
            Json(json!({"rails": {}})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    }
    #[tokio::test]
    #[ignore = "requires an operator-run migrated Postgres test database"]
    async fn og62_pg_viewer_get_and_put_are_403() {
        let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
        let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
        claims.role = Some(Role::Viewer);
        let tenant = *claims.tenant_id.as_uuid();
        let client = pool.get().await.unwrap();
        client.execute("INSERT INTO tenants (id, workos_org_id, name) VALUES ($1, $2, 'viewer policy test')", &[&tenant, &format!("org_viewer_policy_{tenant}")]).await.unwrap();
        let _guard = crate::media_common::test_support::as_claims(claims);
        let mut state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        state.pg = Some(pool);
        let headers = crate::handler_harness::authed();
        assert_eq!(
            read(
                State(state.clone()),
                headers.clone(),
                Query(Scope::default())
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            write(
                State(state),
                headers,
                Query(Scope::default()),
                Json(json!({"rails":{}}))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    #[test]
    fn gwy63_r2_default_behavior_carries_the_custom_bounds() {
        let seed: Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let limits = &default_behavior("R2_secrets_pii")["custom_limits"];
        assert_eq!(
            limits["custom_count"],
            seed["policy"]["guardrail_pii"]["custom_count"]
        );
        assert_eq!(
            limits["custom_pattern_bytes"],
            seed["policy"]["guardrail_pii"]["custom_pattern_bytes"]
        );
    }
    #[test]
    fn gwy60_r7_default_behavior_carries_the_term_bounds() {
        let seed: Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let limits = &default_behavior("R7_topic_competitor")["term_limits"];
        assert_eq!(
            limits["list_count"],
            seed["policy"]["guardrail_terms"]["list_count"]
        );
        assert_eq!(
            limits["term_bytes"],
            seed["policy"]["guardrail_terms"]["term_bytes"]
        );
    }
    #[test]
    fn og30_scope_never_accepts_a_workspace_id_from_input() {
        let tenant = Uuid::new_v4();
        assert_eq!(
            Scope::default().resolve(tenant),
            Some(("workspace", tenant))
        );
        assert!(
            Scope {
                scope: Some("workspace".into()),
                id: Some(Uuid::new_v4())
            }
            .resolve(tenant)
            .is_none()
        );
        assert!(
            Scope {
                scope: Some("key".into()),
                id: None
            }
            .resolve(tenant)
            .is_none()
        );
    }
}
