//! Owner-only issuer registration, serialized with protected admission.
use super::*;
use crate::{
    auth::Claims,
    control_plane::ControlActor,
    db::control_audit::{self, Change},
    server::AppState,
};
use axum::http::HeaderMap;
use principal::Issuer;
type Refusal = (u16, &'static str);
fn unavailable<E>(_: E) -> Refusal {
    (503, "principal_registry_unavailable")
}

#[tracing::instrument(skip_all)]
pub async fn change(
    state: &AppState,
    claims: &Claims,
    actor: &ControlActor,
    headers: &HeaderMap,
    body: &[u8],
    delete: bool,
) -> std::result::Result<Value, Refusal> {
    if claims.auth_method != crate::auth::AuthMethod::JwtBearer || !claims.is_verified_owner() {
        return Err((403, "forbidden"));
    }
    let auth = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((403, "forbidden"))?;
    if crate::auth::verified_session(auth)
        .await
        .map_err(unavailable)?
        .is_none()
    {
        return Err((403, "forbidden"));
    }
    let pool = state
        .pg
        .as_ref()
        .ok_or((503, "principal_registry_unavailable"))?;
    let resolved = state
        .entitlements
        .as_ref()
        .ok_or((503, "principal_registry_unavailable"))?
        .resolved(*claims.tenant_id.as_uuid())
        .await;
    if !enabled(Some(&resolved)) {
        return Err((409, "action_control_disabled"));
    }
    let settings = crate::mcp_policy::settings().map_err(unavailable)?;
    if body.len() > settings.limits.max_request_bytes {
        return Err((400, "principal_invalid"));
    }
    let value = crate::strict_json::from_slice(body).map_err(|_| (400, "principal_invalid"))?;
    let registration: Option<Issuer> = if delete {
        None
    } else {
        Some(serde_json::from_value(value.clone()).map_err(|_| (400, "principal_invalid"))?)
    };
    let issuer = value["issuer"].as_str().ok_or((400, "principal_invalid"))?;
    if delete && value.as_object().is_none_or(|o| o.len() != 1) {
        return Err((400, "principal_invalid"));
    }
    if let Some(config) = &registration {
        principal::validate_issuer(config).map_err(|_| (400, "principal_invalid"))?;
        // Registration performs the same public-address validation as each fetch.
        crate::ssrf_guard::validate_url_pinned(&config.jwks_url)
            .await
            .map_err(|_| (400, "principal_invalid"))?;
    }
    let timeout = std::time::Duration::from_secs(settings.limits.call_timeout_secs);
    tokio::time::timeout(timeout, async {
        let mut db = pool.get().await.map_err(unavailable)?;
        let tx = db.transaction().await.map_err(unavailable)?;
        execution::deadline_tx(&tx, timeout)
            .await
            .map_err(unavailable)?;
        let out = change_tx(&tx, claims, &actor.audit, issuer, registration.as_ref())
            .await
            .map_err(|e| match e.to_string().as_str() {
                "principal_exists" => (409, "principal_exists"),
                "principal_limit" => (409, "principal_limit"),
                "principal_not_found" => (404, "principal_not_found"),
                "unauthorized" => (403, "forbidden"),
                _ => unavailable(e),
            })?;
        tx.commit().await.map_err(unavailable)?;
        Ok(out)
    })
    .await
    .map_err(unavailable)?
}
/// Errors fail CLOSED; callers commit only after the control audit row succeeds.
pub(super) async fn change_tx(
    tx: &Transaction<'_>,
    claims: &Claims,
    actor: &control_audit::Actor,
    issuer: &str,
    config: Option<&Issuer>,
) -> Result<Value> {
    ensure!(
        claims.auth_method == crate::auth::AuthMethod::JwtBearer
            && claims.is_verified_owner()
            && !claims.sub.is_empty(),
        "unauthorized"
    );
    let tenant = claims.tenant_id.as_uuid();
    tx.query_one("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", &[tenant])
        .await?;
    let prior = tx
        .query_opt(
            "SELECT id FROM tenant_principal_issuers WHERE tenant_id=$1 AND issuer=$2",
            &[tenant, &issuer],
        )
        .await?;
    let (id, action, before, after) = if let Some(config) = config {
        principal::validate_issuer(config)?;
        ensure!(config.issuer == issuer, "principal_invalid");
        ensure!(prior.is_none(), "principal_exists");
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM tenant_principal_issuers WHERE tenant_id=$1",
                &[tenant],
            )
            .await?
            .get(0);
        ensure!(
            count < i64::try_from(crate::mcp_policy::settings()?.principal.max_issuers)?,
            "principal_limit"
        );
        let id = Uuid::new_v4();
        let algs = config
            .allowed_algs
            .iter()
            .map(|a| serde_json::to_value(a).and_then(serde_json::from_value::<String>))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        tx.execute("INSERT INTO tenant_principal_issuers (tenant_id,id,issuer,jwks_url,audience,allowed_algs,created_by_sub,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp())", &[tenant,&id,&issuer,&config.jwks_url,&config.audience,&algs,&claims.sub]).await?;
        (
            id,
            "principal_issuer.register",
            None,
            Some(serde_json::to_value(config)?),
        )
    } else {
        let id: Uuid = prior.context("principal_not_found")?.get(0);
        tx.execute(
            "DELETE FROM tenant_principal_issuers WHERE tenant_id=$1 AND id=$2",
            &[tenant, &id],
        )
        .await?;
        (
            id,
            "principal_issuer.delete",
            Some(json!({"issuer":issuer})),
            None,
        )
    };
    control_audit::record(
        tx,
        &claims.tenant_id,
        actor,
        Change {
            action,
            target_type: "principal_issuer",
            target_id: id.to_string(),
            before,
            after,
        },
    )
    .await?;
    Ok(json!({"id":id,"issuer":issuer}))
}
