//! Tenant-owned hook configuration. Credentials never enter reads or control audit.
use super::hooks::{Config, Hook, credential_aad, limits};
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub const SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("guardrail_hooks", "tenant_id"),
    ("guardrail_hooks", "id"),
    ("guardrail_hooks", "config"),
    ("guardrail_hooks", "ciphertext_b64"),
    ("guardrail_hooks", "updated_at"),
    ("guardrail_hooks", "updated_by"),
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    config: Config,
    signing_secret: Option<String>,
    api_key: Option<String>,
}
impl Upload {
    fn parts(self) -> Option<(Config, SecretString)> {
        let signing = self.signing_secret.map(SecretString::from);
        let key = self.api_key.map(SecretString::from);
        let secret = match (self.config.adapter.is_some(), signing, key) {
            (false, Some(secret), None) | (true, None, Some(secret)) => secret,
            _ => return None,
        };
        Some((self.config, secret))
    }
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/guardrails/hooks", get(read))
        .route("/v1/guardrails/hooks/{id}", put(write).delete(remove))
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
    let control = crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::EditPolicies,
        headers,
    )
    .await
    .map_err(IntoResponse::into_response)?;
    Ok((claims, control.audit))
}

/// Called only by the cached entitlement resolver. Query/decode failures retain
/// its last-known snapshot; a cold failure refuses custom-policy evaluation.
pub async fn load(
    client: &tokio_postgres::Client,
    tenant: &Uuid,
    revision: &mut String,
) -> anyhow::Result<Vec<Hook>> {
    let rows=client.query("SELECT id, config, ciphertext_b64, updated_at FROM guardrail_hooks WHERE tenant_id = $1 ORDER BY id",&[tenant]).await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let cap = limits().ok_or_else(|| anyhow::anyhow!("hook safety reference unavailable"))?;
    anyhow::ensure!(
        rows.len() <= cap.max_hooks,
        "stored hook count exceeds bound"
    );
    let master = crate::byok::master_key()
        .ok_or_else(|| anyhow::anyhow!("hook credential key unavailable"))?;
    let mut hooks = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.get(0);
        let value: Value = row.get(1);
        let ciphertext: String = row.get(2);
        let updated: chrono::DateTime<chrono::Utc> = row.get(3);
        let config: Config = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("stored hook configuration invalid"))?;
        anyhow::ensure!(config.valid(), "stored hook configuration invalid");
        let secret = master.decrypt_with_context(
            &ciphertext,
            &credential_aad(tenant, &config.credential_key(id)),
        )?;
        anyhow::ensure!(
            config.credential_valid(&secret),
            "stored hook credential invalid"
        );
        use std::fmt::Write as _;
        let _ = write!(revision, "hook:{id}:{updated};");
        hooks.push(Hook {
            id,
            config,
            ciphertext,
            secret: Arc::new(secret),
            #[cfg(test)]
            answer: None,
        });
    }
    Ok(hooks)
}
#[tracing::instrument(skip_all)]
async fn read(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (claims, _) = match authorize(&headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(pool) = &state.pg else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable");
    };
    let client = match pool.get().await {
        Ok(c) => c,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable"),
    };
    let rows = match client
        .query(
            "SELECT id, config, updated_at FROM guardrail_hooks WHERE tenant_id = $1 ORDER BY id",
            &[claims.tenant_id.as_uuid()],
        )
        .await
    {
        Ok(r) => r,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable"),
    };
    let values: Result<Vec<Value>, ()> = rows.into_iter().map(|r| {
        let config:Config=serde_json::from_value(r.get::<_,Value>(1)).map_err(|_| ())?;
        if !config.valid() {return Err(())}
        Ok(json!({"id":r.get::<_,Uuid>(0),"config":config,"updated_at":r.get::<_,chrono::DateTime<chrono::Utc>>(2),"credential_configured":true}))
    }).collect();
    let values = match values {
        Ok(v) => v,
        Err(()) => return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable"),
    };
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({"hooks":values})),
    )
        .into_response()
}
#[derive(Debug, PartialEq, Eq)]
enum WriteStatus {
    Written,
    Missing,
    Limit,
}

/// Fail-CLOSED: audit failure rolls back both creates and deletes.
async fn persist(
    pool: &crate::db::DbPool,
    tenant: &tracelane_shared::TenantId,
    id: Uuid,
    value: Option<(&Value, &str)>,
    actor: &crate::db::control_audit::Actor,
) -> anyhow::Result<WriteStatus> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.query_one(
        "SELECT id FROM tenants WHERE id = $1 FOR UPDATE",
        &[tenant.as_uuid()],
    )
    .await?;
    let before: Option<Value> = tx
        .query_opt(
            "SELECT config FROM guardrail_hooks WHERE tenant_id = $1 AND id = $2",
            &[tenant.as_uuid(), &id],
        )
        .await?
        .map(|r| r.get(0));
    if value.is_none() && before.is_none() {
        return Ok(WriteStatus::Missing);
    }
    if value.is_some() && before.is_none() {
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM guardrail_hooks WHERE tenant_id = $1",
                &[tenant.as_uuid()],
            )
            .await?
            .get(0);
        let max = limits()
            .ok_or_else(|| anyhow::anyhow!("hook reference unavailable"))?
            .max_hooks;
        if !usize::try_from(count).is_ok_and(|n| n < max) {
            return Ok(WriteStatus::Limit);
        }
    }
    let after = if let Some((config, ciphertext)) = value {
        tx.execute("INSERT INTO guardrail_hooks (tenant_id, id, config, ciphertext_b64, updated_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,id) DO UPDATE SET config=EXCLUDED.config, ciphertext_b64=EXCLUDED.ciphertext_b64, updated_by=EXCLUDED.updated_by, updated_at=clock_timestamp()",&[tenant.as_uuid(),&id,config,&ciphertext,&actor.sub]).await?;
        Some(config.clone())
    } else {
        tx.execute(
            "DELETE FROM guardrail_hooks WHERE tenant_id = $1 AND id = $2",
            &[tenant.as_uuid(), &id],
        )
        .await?;
        None
    };
    crate::db::control_audit::record(
        &tx,
        tenant,
        actor,
        crate::db::control_audit::Change {
            action: if value.is_some() {
                "guardrail.hook.put"
            } else {
                "guardrail.hook.delete"
            },
            target_type: "guardrail_hook",
            target_id: id.to_string(),
            before,
            after,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(WriteStatus::Written)
}
#[tracing::instrument(skip_all)]
async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(upload): Json<Upload>,
) -> Response {
    let (claims, actor) = match authorize(&headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some((config, secret)) = upload.parts() else {
        return error(StatusCode::BAD_REQUEST, "invalid_hook_credential");
    };
    let Some(cap) = limits() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable");
    };
    if !config.valid() || !config.credential_valid(&secret) {
        return error(StatusCode::BAD_REQUEST, "invalid_hook");
    }
    match tokio::time::timeout(
        std::time::Duration::from_millis(cap.timeout_ms),
        crate::ssrf_guard::validate_url_pinned(&config.endpoint),
    )
    .await
    {
        Ok(Ok(_)) => (),
        _ => return error(StatusCode::BAD_REQUEST, "invalid_hook_destination"),
    }
    let Some(pool) = &state.pg else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable");
    };
    let Some(master) = crate::byok::master_key() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable");
    };
    let ciphertext = match master.encrypt_with_context(
        &secret,
        &credential_aad(claims.tenant_id.as_uuid(), &config.credential_key(id)),
    ) {
        Ok(c) => c,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable"),
    };
    let value = match serde_json::to_value(&config) {
        Ok(v) => v,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_hook"),
    };
    match persist(
        pool,
        &claims.tenant_id,
        id,
        Some((&value, &ciphertext)),
        &actor,
    )
    .await
    {
        Ok(WriteStatus::Written) => {
            if let Some(cache) = &state.entitlements {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            (
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                Json(json!({"id":id,"config":value,"credential_configured":true})),
            )
                .into_response()
        }
        Ok(WriteStatus::Limit) => error(StatusCode::CONFLICT, "hook_limit_reached"),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "hook_write_failed"),
    }
}
#[tracing::instrument(skip_all)]
async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let (claims, actor) = match authorize(&headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(pool) = &state.pg else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "hooks_unavailable");
    };
    match persist(pool, &claims.tenant_id, id, None, &actor).await {
        Ok(WriteStatus::Written) => {
            if let Some(cache) = &state.entitlements {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(WriteStatus::Missing) => error(StatusCode::NOT_FOUND, "hook_not_found"),
        Ok(WriteStatus::Limit) => error(StatusCode::CONFLICT, "hook_limit_reached"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "hook_write_failed"),
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn og31_hook_writes_require_edit_policies() {
        for role in [
            crate::auth::Role::Member,
            crate::auth::Role::Viewer,
            crate::auth::Role::Billing,
        ] {
            let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
            claims.role = Some(role);
            let _guard = crate::media_common::test_support::as_claims(claims);
            let error = match authorize(&crate::handler_harness::authed()).await {
                Err(e) => e,
                Ok(_) => panic!("role must be refused"),
            };
            assert_eq!(error.status(), StatusCode::FORBIDDEN);
        }
    }
    #[test]
    fn og32_api_key_payload_is_a_supported_write_shape() {
        let hook = super::super::adapter_tests::fixtures().remove(0);
        let body = json!({"config":hook.config,"api_key":"synthetic-vendor-key"});
        assert!(serde_json::from_value::<Upload>(body).is_ok());
    }

    #[test]
    fn og32_upload_selects_exactly_one_credential_for_its_kind() {
        for hook in super::super::adapter_tests::fixtures() {
            let value = json!({"config":hook.config,"api_key":"short-vendor-key"});
            let (config, key) = serde_json::from_value::<Upload>(value.clone())
                .unwrap()
                .parts()
                .unwrap();
            assert!(config.credential_valid(&key));
            let mut mixed = value.clone();
            mixed["signing_secret"] = json!("0123456789abcdef0123456789abcdef");
            assert!(
                serde_json::from_value::<Upload>(mixed)
                    .unwrap()
                    .parts()
                    .is_none()
            );
            let mut missing = value;
            missing.as_object_mut().unwrap().remove("api_key");
            assert!(
                serde_json::from_value::<Upload>(missing)
                    .unwrap()
                    .parts()
                    .is_none()
            );
        }
        let config = super::super::hooks::fixture().config;
        let wrong = json!({"config":config,"api_key":"wrong-kind"});
        assert!(
            serde_json::from_value::<Upload>(wrong)
                .unwrap()
                .parts()
                .is_none()
        );
        assert!(!config.credential_valid(&SecretString::from("short")));
    }

    #[test]
    fn og31_upload_cannot_supply_tenant_or_unknown_config_fields() {
        let mut value = json!({"config":super::super::hooks::fixture().config,"signing_secret":"FAKEtestkeyDONOTUSE-hook-signing-00"});
        assert!(serde_json::from_value::<Upload>(value.clone()).is_ok());
        value["tenant_id"] = json!(Uuid::new_v4());
        assert!(serde_json::from_value::<Upload>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("tenant_id");
        value["config"]["api_key"] = json!("forbidden");
        assert!(serde_json::from_value::<Upload>(value).is_err());
    }
    #[tokio::test]
    #[ignore = "requires an operator-run migrated Postgres test database"]
    async fn og31_pg_hook_ownership_and_atomic_audit_rollback() {
        let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
        let client = pool.get().await.unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        for id in [a, b] {
            client
                .execute(
                    "INSERT INTO tenants (id,workos_org_id,name) VALUES ($1,$2,'hook test')",
                    &[&id, &format!("org_hook_{id}")],
                )
                .await
                .unwrap();
        }
        let ta = tracelane_shared::TenantId::from_jwt_claim(a);
        let tb = tracelane_shared::TenantId::from_jwt_claim(b);
        let id = Uuid::new_v4();
        let actor = crate::db::control_audit::Actor {
            sub: "test-admin".into(),
            role: "admin",
            auth_method: "workos_session",
            request_id: Uuid::new_v4().to_string(),
            ip: None,
            user_agent: None,
        };
        let before = serde_json::to_value(super::super::hooks::fixture().config).unwrap();
        assert_eq!(
            persist(&pool, &ta, id, Some((&before, "test-ciphertext")), &actor)
                .await
                .unwrap(),
            WriteStatus::Written
        );
        assert_eq!(
            persist(&pool, &tb, id, None, &actor).await.unwrap(),
            WriteStatus::Missing
        );
        let count:i64=client.query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 AND action = 'guardrail.hook.put'",&[&a]).await.unwrap().get(0);
        assert_eq!(count, 1);
        client.batch_execute("ALTER TABLE admin_audit_log ADD CONSTRAINT og31_refuse CHECK (action <> 'guardrail.hook.put') NOT VALID").await.unwrap();
        let mut after = before.clone();
        after["timeout_ms"] = json!(15);
        assert!(
            persist(&pool, &ta, id, Some((&after, "replacement")), &actor)
                .await
                .is_err()
        );
        let stored: Value = client
            .query_one(
                "SELECT config FROM guardrail_hooks WHERE tenant_id = $1 AND id = $2",
                &[&a, &id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(stored, before);
    }
}
