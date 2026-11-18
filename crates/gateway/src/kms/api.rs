//! Authenticated KMS lifecycle. Every mutation and its audit row commit together.
use super::{
    KeyVault, KmsError, VaultError,
    backend::{Backend, Config, KmsBackend},
    vault,
};
use crate::{auth::capability::Capability, server::AppState};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};
use tracelane_shared::TenantId;
use uuid::Uuid;
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/security/kms", get(read).put(write).delete(delete))
        .route("/v1/security/kms/migrate", post(migrate))
        .route("/v1/security/kms/rewrap", post(rewrap))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetRequest {
    backend: String,
    key_ref: String,
    params: Value,
    #[serde(default, deserialize_with = "secret")]
    secret: Option<SecretString>,
}

fn secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
    Option::<String>::deserialize(d).map(|s| s.map(SecretString::from))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    confirm: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rewrap {
    key_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delete {
    mode: DeleteMode,
    confirm: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeleteMode {
    Unseal,
    Abandon,
}
struct Error(StatusCode, &'static str);
impl From<VaultError> for Error {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Lookup => Self(StatusCode::SERVICE_UNAVAILABLE, "kms_unavailable"),
            VaultError::Invalid => Self(StatusCode::CONFLICT, "provider_key_unusable"),
            VaultError::Kms(KmsError::Unavailable) => {
                Self(StatusCode::SERVICE_UNAVAILABLE, "kms_unavailable")
            }
            VaultError::Kms(KmsError::Denied) => Self(StatusCode::FORBIDDEN, "kms_access_denied"),
        }
    }
}
impl From<KmsError> for Error {
    fn from(e: KmsError) -> Self {
        VaultError::Kms(e).into()
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "kms_unavailable")
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut response = (
            self.0,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "error":self.1}
            )),
        )
            .into_response();
        if self.1 == "kms_unavailable"
            && let Some(l) = super::limits()
            && let Ok(h) = l.failure_backoff_secs.to_string().parse()
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, h);
        }
        response
    }
}

async fn actor(
    headers: &HeaderMap,
    cap: Capability,
) -> Result<crate::control_plane::ControlActor, Response> {
    let claims = crate::auth::validate_authorization(
        headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default(),
    )
    .await
    .map_err(|e| {
        Error(crate::auth::failure(&e).0, crate::auth::failure_code(&e)).into_response()
    })?;
    crate::control_plane::require_control(&claims, cap, headers)
        .await
        .map_err(IntoResponse::into_response)
}

fn response(value: Result<Value, Error>) -> Response {
    match value {
        Ok(v) => ([(axum::http::header::CACHE_CONTROL, "no-store")], Json(v)).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn client(state: &AppState) -> Result<deadpool_postgres::Client, Error> {
    state
        .pg
        .as_ref()
        .ok_or(Error(StatusCode::SERVICE_UNAVAILABLE, "kms_unavailable"))?
        .get()
        .await
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "kms_unavailable"))
}

fn master() -> Result<&'static crate::byok::ByokMasterKey, Error> {
    crate::byok::master_key().ok_or(Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "kms_backend_unavailable",
    ))
}

async fn lock_tenant(tx: &tokio_postgres::Transaction<'_>, tenant: &TenantId) -> Result<(), Error> {
    tx.query_one(
        "SELECT id FROM tenants WHERE id = $1 FOR UPDATE",
        &[tenant.as_uuid()],
    )
    .await?;
    Ok(())
}

async fn audit(
    tx: &tokio_postgres::Transaction<'_>,
    a: &crate::control_plane::ControlActor,
    action: &str,
    before: Option<Value>,
    after: Option<Value>,
) -> Result<(), Error> {
    crate::db::control_audit::record(
        tx,
        &a.tenant_id,
        &a.audit,
        crate::db::control_audit::Change {
            action,
            target_type: "tenant_kms",
            target_id: a.tenant_id.to_string(),
            before,
            after,
        },
    )
    .await
    .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "kms_unavailable"))?;
    Ok(())
}

fn summary(c: &vault::Configuration) -> Value {
    json!({
        "configuration":c.backend.config,"key_ref":c.backend.key_ref,"dek_id":c.id}
    )
}

/// # Errors
/// Fail CLOSED on authorization and storage errors; never returns wrapped or raw keys.
#[tracing::instrument(skip_all)]
async fn read(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let a = match actor(&headers, Capability::ViewSettings).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    response(read_inner(&state, &a).await)
}

async fn read_inner(
    state: &AppState,
    a: &crate::control_plane::ControlActor,
) -> Result<Value, Error> {
    let master = master()?;
    let client = client(state).await?;
    let v = KeyVault::global()?;
    // A read takes no fence (H1): it neither calls the KMS nor writes.
    let config = vault::load(&**client, &a.tenant_id, master).await?;
    let rows = client
        .query(
            "SELECT ciphertext_b64 FROM provider_keys WHERE tenant_id = $1 UNION ALL SELECT credential_ct FROM mcp_servers WHERE tenant_id=$1 AND credential_ct IS NOT NULL",
            &[a.tenant_id.as_uuid()],
        )
        .await?;
    let platform = rows
        .iter()
        .filter(|r| {
            !crate::byok::ByokMasterKey::is_customer_envelope(r.get::<_, String>(0).as_str())
        })
        .count();
    let (last, error) = config
        .as_ref()
        .map_or((None, None), |c| v.status(&a.tenant_id, c));
    let status = if config.is_some() {
        "configured"
    } else {
        "not_configured"
    };
    Ok(json!({
        "kms": config.as_ref().map(summary),
        "status": status,
        "rows_on_platform_kek": platform,
        "last_unwrap_ok_at": last,
        "last_unwrap_error": error,
        "unwrap_status_scope": "this_process",
        "revocation_bound_secs": super::limits().map(|l|l.dek_cache_ttl_secs),
    }))
}

/// # Errors
/// Fail CLOSED. Probes and replacement envelopes must all succeed before commit.
#[tracing::instrument(skip_all)]
async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetRequest>,
) -> Response {
    let a = match actor(&headers, Capability::ManageSecurity).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    response(write_inner(&state, &a, req).await)
}

async fn write_inner(
    state: &AppState,
    a: &crate::control_plane::ControlActor,
    req: SetRequest,
) -> Result<Value, Error> {
    // Absent control plane is unprivileged; existing encryption is never removed
    // because an entitlement changed. The flag controls setting new configuration.
    let entitled = match &state.entitlements {
        Some(e) => e.resolved(*a.tenant_id.as_uuid()).await.f_customer_kms,
        None => false,
    };
    if !entitled {
        return Err(Error(StatusCode::FORBIDDEN, "byok_cmk_required"));
    }
    let config: Config = serde_json::from_value(json!({
        "backend":req.backend,"params":req.params}
    ))
    .map_err(|_| Error(StatusCode::BAD_REQUEST, "invalid_field"))?;
    let backend = Backend {
        config,
        key_ref: req.key_ref,
        secret: req.secret,
    };
    if !backend.valid() {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid_field"));
    }
    backend.authorize(&a.tenant_id)?;
    if !backend.ready() {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "kms_backend_unavailable",
        ));
    }
    backend
        .validate_destination()
        .await
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "ssrf_blocked"))?;
    let master = master()?;
    let v = KeyVault::global()?;
    // H1: every customer-KMS call happens BEFORE the tenant fence is taken — the probe,
    // and recovering the current DEK — and the configuration they used is re-checked
    // (CAS) inside the fence and the transaction.
    let id = Uuid::new_v4();
    let dek = vault::fresh_dek()?;
    let wrapped = vault::wrap_probe(&backend, &a.tenant_id, id, &dek)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "kms_probe_failed"))?;
    let seen = vault::load(&**client(state).await?, &a.tenant_id, master).await?;
    let old_dek = match &seen {
        // A refreshed Vault token may be the only credential that can unwrap the
        // existing key. Try the submitted same-backend/key configuration first.
        Some(old)
            if serde_json::to_value(&old.backend.config).ok()
                == serde_json::to_value(&backend.config).ok()
                && old.backend.key_ref == backend.key_ref =>
        {
            Some(super::unbind_dek(
                &a.tenant_id,
                old.id,
                &v.kms_call(&a.tenant_id, async {
                    v.check_revision(&a.tenant_id, old.revision)?;
                    let opened = backend.unwrap(&a.tenant_id, old.id, &old.wrapped).await?;
                    v.check_revision(&a.tenant_id, old.revision)?;
                    Ok(opened)
                })
                .await?,
            )?)
        }
        Some(old) => {
            let (d, _) = v
                .dek(
                    &old.backend,
                    &a.tenant_id,
                    old.id,
                    &old.wrapped,
                    old.revision,
                )
                .await?;
            Some(Zeroizing::new(**d))
        }
        None => None,
    };
    let _lock = v.lock(&a.tenant_id).await?;
    let mut client = client(state).await?;
    let tx = client.transaction().await?;
    lock_tenant(&tx, &a.tenant_id).await?;
    let old = vault::load(&*tx, &a.tenant_id, master).await?;
    if !same_dek(old.as_ref(), seen.as_ref()) {
        return Err(Error(StatusCode::CONFLICT, "kms_conflict"));
    }
    let rows = secret_rows(&tx, &a.tenant_id).await?;
    // Updating KMS auth/key configuration re-seals existing v4 rows atomically.
    // Initial adoption leaves platform rows for the explicit migrate action.
    if let (Some(old), Some(old_dek)) = (&old, &old_dek) {
        for (provider, blob, mcp) in &rows {
            if crate::byok::ByokMasterKey::kek_id_of(blob).is_some() {
                continue;
            }
            let plain = super::open(&a.tenant_id, provider, old.id, old_dek, blob)
                .map_err(|_| VaultError::Invalid)?;
            let sealed = super::seal(&a.tenant_id, provider, id, &dek, &plain)?;
            save_secret(&tx, &a.tenant_id, provider, &sealed, *mcp).await?;
        }
    }
    let value = serde_json::to_value(&backend.config)
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "invalid_field"))?;
    let kind = value["backend"]
        .as_str()
        .ok_or(Error(StatusCode::BAD_REQUEST, "invalid_field"))?;
    let secret = backend
        .secret
        .as_ref()
        .map(|s| {
            master
                .encrypt_with_context(s, &crate::byok::kms_config_aad(a.tenant_id.as_uuid()))
                .map_err(|_| VaultError::Invalid)
        })
        .transpose()?;
    tx.execute("INSERT INTO tenant_kms_configs (tenant_id, backend, key_ref, params, secret_enc, updated_by) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id) DO UPDATE SET backend=EXCLUDED.backend,key_ref=EXCLUDED.key_ref,params=EXCLUDED.params,secret_enc=EXCLUDED.secret_enc,updated_by=EXCLUDED.updated_by,updated_at=now()",&[a.tenant_id.as_uuid(),&kind,&backend.key_ref,&value["params"],&secret,&a.audit.sub]).await?;
    tx.execute("UPDATE tenant_data_keys SET retired_at = now() WHERE tenant_id = $1 AND retired_at IS NULL",&[a.tenant_id.as_uuid()]).await?;
    tx.execute(
        "INSERT INTO tenant_data_keys (id,tenant_id,wrapped_dek,key_ref) VALUES ($1,$2,$3,$4)",
        &[&id, a.tenant_id.as_uuid(), &wrapped, &backend.key_ref],
    )
    .await?;
    let new = vault::Configuration {
        backend,
        id,
        wrapped,
        revision: v.revision(&a.tenant_id),
    };
    let result = summary(&new);
    audit(
        &tx,
        a,
        "security.kms.set",
        old.as_ref().map(summary),
        Some(result.clone()),
    )
    .await?;
    tx.commit().await?;
    v.invalidate(&a.tenant_id);
    if let Some(cache) = &state.entitlements {
        cache.invalidate(*a.tenant_id.as_uuid()).await;
    }
    crate::mcp_inspection::evict(*a.tenant_id.as_uuid());
    Ok(result)
}
use secrecy::zeroize::Zeroizing;

/// H1's CAS: the configuration a write recovered its DEK under (before the fence) is
/// still the current one (inside the fence and transaction). Compares the DEK row — id,
/// wrapped bytes and key reference — never secrets.
fn same_dek(now: Option<&vault::Configuration>, seen: Option<&vault::Configuration>) -> bool {
    now.map(dek_row) == seen.map(dek_row)
}
fn dek_row(c: &vault::Configuration) -> (Uuid, Vec<u8>, String) {
    (c.id, c.wrapped.clone(), c.backend.key_ref.clone())
}

/// The current configuration and its DEK, read and unwrapped OUTSIDE the tenant fence
/// (H1). `None` = no KMS configured.
async fn current_dek(
    state: &AppState,
    v: &KeyVault,
    tenant: &TenantId,
    master: &crate::byok::ByokMasterKey,
) -> Result<Option<(vault::Configuration, Zeroizing<[u8; 32]>)>, Error> {
    let Some(c) = vault::load(&**client(state).await?, tenant, master).await? else {
        return Ok(None);
    };
    let (dek, _) = v
        .dek(&c.backend, tenant, c.id, &c.wrapped, c.revision)
        .await?;
    Ok(Some((c, Zeroizing::new(**dek))))
}

/// # Errors
/// Fail CLOSED: any decrypt, UPDATE, or audit failure rolls back all provider rows.
#[tracing::instrument(skip_all)]
async fn migrate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Confirmation>,
) -> Response {
    let a = match actor(&headers, Capability::ManageSecurity).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    response(
        async {
            if !req.confirm {
                return Err(Error(StatusCode::BAD_REQUEST, "confirmation_required"));
            }
            let master = master()?;
            let v = KeyVault::global()?;
            // H1: the unwrap happens before the fence; the fence re-checks the DEK row.
            let (seen, dek) = current_dek(&state, v, &a.tenant_id, master)
                .await?
                .ok_or(Error(StatusCode::CONFLICT, "kms_not_configured"))?;
            let _lock = v.lock(&a.tenant_id).await?;
            let mut client = client(&state).await?;
            let tx = client.transaction().await?;
            lock_tenant(&tx, &a.tenant_id).await?;
            let c = vault::load(&*tx, &a.tenant_id, master)
                .await?
                .ok_or(Error(StatusCode::CONFLICT, "kms_not_configured"))?;
            if !same_dek(Some(&c), Some(&seen)) {
                return Err(Error(StatusCode::CONFLICT, "kms_conflict"));
            }
            let count = migrate_keys(&tx, &a.tenant_id, master, c.id, &dek).await?;
            let result = json!({
                "migrated":count,"dek_id":c.id}
            );
            audit(&tx, &a, "security.kms.migrate", None, Some(result.clone())).await?;
            tx.commit().await?;
            v.invalidate(&a.tenant_id);
            if let Some(cache) = &state.entitlements {
                cache.invalidate(*a.tenant_id.as_uuid()).await;
            }
            crate::mcp_inspection::evict(*a.tenant_id.as_uuid());
            Ok(result)
        }
        .await,
    )
}
// Every vault-encrypted credential participates in the same atomic lifecycle.
async fn secret_rows(
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
) -> Result<Vec<(String, String, bool)>, Error> {
    let mut rows = Vec::new();
    for r in tx.query("SELECT CASE WHEN label='default' THEN provider_id ELSE provider_id||':'||label END,ciphertext_b64 FROM provider_keys WHERE tenant_id=$1 ORDER BY provider_id,label FOR UPDATE",&[tenant.as_uuid()]).await? {rows.push((r.get(0),r.get(1),false));}
    for r in tx.query("SELECT 'mcp-server-credential:'||id::text,credential_ct FROM mcp_servers WHERE tenant_id=$1 AND credential_ct IS NOT NULL ORDER BY id FOR UPDATE",&[tenant.as_uuid()]).await? {rows.push((r.get(0),r.get(1),true));}
    Ok(rows)
}
async fn save_secret(
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
    purpose: &str,
    blob: &str,
    mcp: bool,
) -> Result<(), Error> {
    let query = if mcp {
        "UPDATE mcp_servers SET credential_ct=$3,updated_at=now() WHERE tenant_id=$1 AND 'mcp-server-credential:'||id::text=$2"
    } else {
        "UPDATE provider_keys SET ciphertext_b64=$3,updated_at=now() WHERE tenant_id=$1 AND (CASE WHEN label='default' THEN provider_id ELSE provider_id||':'||label END)=$2"
    };
    tx.execute(query, &[tenant.as_uuid(), &purpose, &blob])
        .await?;
    Ok(())
}

/// Re-seal within the caller's transaction; a bad row refuses the whole migration.
async fn migrate_keys(
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
    master: &crate::byok::ByokMasterKey,
    id: Uuid,
    dek: &[u8; 32],
) -> Result<u64, Error> {
    let mut count = 0;
    let rows = secret_rows(tx, tenant).await?;
    for (provider, blob, mcp) in rows {
        if crate::byok::ByokMasterKey::kek_id_of(&blob).is_none() {
            super::open(tenant, &provider, id, dek, &blob).map_err(|_| VaultError::Invalid)?;
            continue;
        }
        let plain = master
            .decrypt_with_context(&blob, &crate::byok::provider_key_aad(tenant, &provider))
            .map_err(|_| VaultError::Invalid)?;
        let sealed = super::seal(tenant, &provider, id, dek, &plain)?;
        save_secret(tx, tenant, &provider, &sealed, mcp).await?;
        count += 1;
    }
    Ok(count)
}

/// # Errors
/// Fail CLOSED. The DEK and provider envelopes stay unchanged during a rewrap.
#[tracing::instrument(skip_all)]
async fn rewrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Rewrap>,
) -> Response {
    let a = match actor(&headers, Capability::ManageSecurity).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    response(rewrap_inner(&state, &a, req).await)
}

async fn rewrap_inner(
    state: &AppState,
    a: &crate::control_plane::ControlActor,
    req: Rewrap,
) -> Result<Value, Error> {
    let master = master()?;
    let v = KeyVault::global()?;
    // H1: unwrap + probe-wrap under the new key happen before the fence; inside it the
    // DEK row they used is re-checked.
    let (mut c, dek) = current_dek(state, v, &a.tenant_id, master)
        .await?
        .ok_or(Error(StatusCode::CONFLICT, "kms_not_configured"))?;
    let before = summary(&c);
    let seen = dek_row(&c);
    c.backend.key_ref = req.key_ref;
    if !c.backend.valid() {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid_field"));
    }
    let wrapped = vault::wrap_probe(&c.backend, &a.tenant_id, c.id, &dek).await?;
    let _lock = v.lock(&a.tenant_id).await?;
    let mut client = client(state).await?;
    let tx = client.transaction().await?;
    lock_tenant(&tx, &a.tenant_id).await?;
    let current = vault::load(&*tx, &a.tenant_id, master)
        .await?
        .ok_or(Error(StatusCode::CONFLICT, "kms_not_configured"))?;
    if dek_row(&current) != seen {
        return Err(Error(StatusCode::CONFLICT, "kms_conflict"));
    }
    tx.execute("UPDATE tenant_data_keys SET key_ref=$3,wrapped_dek=$4 WHERE tenant_id=$1 AND id=$2 AND retired_at IS NULL",&[a.tenant_id.as_uuid(),&c.id,&c.backend.key_ref,&wrapped]).await?;
    tx.execute("UPDATE tenant_kms_configs SET key_ref=$2,updated_at=now(),updated_by=$3 WHERE tenant_id=$1",&[a.tenant_id.as_uuid(),&c.backend.key_ref,&a.audit.sub]).await?;
    let result = summary(&c);
    audit(
        &tx,
        a,
        "security.kms.rewrap",
        Some(before),
        Some(result.clone()),
    )
    .await?;
    tx.commit().await?;
    v.invalidate(&a.tenant_id);
    if let Some(cache) = &state.entitlements {
        cache.invalidate(*a.tenant_id.as_uuid()).await;
    }
    crate::mcp_inspection::evict(*a.tenant_id.as_uuid());
    Ok(result)
}

/// # Errors
/// Fail CLOSED. Abandon can recover from revoked KMS access without decrypting.
#[tracing::instrument(skip_all)]
async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Delete>,
) -> Response {
    let a = match actor(&headers, Capability::ManageSecurity).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    response(delete_inner(&state, &a, req).await)
}

async fn delete_inner(
    state: &AppState,
    a: &crate::control_plane::ControlActor,
    req: Delete,
) -> Result<Value, Error> {
    if !req.confirm {
        return Err(Error(StatusCode::BAD_REQUEST, "confirmation_required"));
    }
    let master = master()?;
    let v = KeyVault::global()?;
    // H1: Unseal needs the DEK — unwrapped before the fence. Abandon needs no KMS call
    // (it is how a tenant recovers from revoked KMS access).
    let unseal = match req.mode {
        DeleteMode::Unseal => Some(
            current_dek(state, v, &a.tenant_id, master)
                .await?
                .ok_or(Error(StatusCode::CONFLICT, "kms_not_configured"))?,
        ),
        DeleteMode::Abandon => None,
    };
    let _lock = v.lock(&a.tenant_id).await?;
    let mut client = client(state).await?;
    let tx = client.transaction().await?;
    lock_tenant(&tx, &a.tenant_id).await?;
    let c = vault::load(&*tx, &a.tenant_id, master)
        .await?
        .ok_or(Error(StatusCode::CONFLICT, "kms_not_configured"))?;
    if let Some((seen, _)) = &unseal
        && !same_dek(Some(&c), Some(seen))
    {
        return Err(Error(StatusCode::CONFLICT, "kms_conflict"));
    }
    let (provider_count, mcp_count) = match req.mode {
        DeleteMode::Abandon => {
            let mcp=tx.execute("UPDATE mcp_servers SET credential_ct=NULL,credential_last4=NULL,auth_mode='none',enabled=false,updated_at=now() WHERE tenant_id=$1 AND credential_ct IS NOT NULL", &[a.tenant_id.as_uuid()]).await?;
            let providers = tx
                .execute(
                    "DELETE FROM provider_keys WHERE tenant_id=$1",
                    &[a.tenant_id.as_uuid()],
                )
                .await?;
            (providers, mcp)
        }
        DeleteMode::Unseal => {
            let mut count = (0u64, 0u64);
            for (provider, blob, mcp) in secret_rows(&tx, &a.tenant_id).await? {
                if crate::byok::ByokMasterKey::kek_id_of(&blob).is_some() {
                    master
                        .decrypt_with_context(
                            &blob,
                            &crate::byok::provider_key_aad(&a.tenant_id, &provider),
                        )
                        .map_err(|_| VaultError::Invalid)?;
                    continue;
                }
                let Some((_, dek)) = &unseal else {
                    return Err(Error(StatusCode::CONFLICT, "kms_conflict"));
                };
                let plain = super::open(&a.tenant_id, &provider, c.id, dek, &blob)
                    .map_err(|_| VaultError::Invalid)?;
                let sealed = master
                    .encrypt_with_context(
                        &plain,
                        &crate::byok::provider_key_aad(&a.tenant_id, &provider),
                    )
                    .map_err(|_| VaultError::Invalid)?;
                save_secret(&tx, &a.tenant_id, &provider, &sealed, mcp).await?;
                if mcp { count.1 += 1 } else { count.0 += 1 }
            }
            count
        }
    };
    tx.execute(
        "DELETE FROM tenant_kms_configs WHERE tenant_id=$1",
        &[a.tenant_id.as_uuid()],
    )
    .await?;
    tx.execute(
        "DELETE FROM tenant_data_keys WHERE tenant_id=$1",
        &[a.tenant_id.as_uuid()],
    )
    .await?;
    let mode = match req.mode {
        DeleteMode::Unseal => "unseal",
        DeleteMode::Abandon => "abandon",
    };
    let result =
        json!({ "mode": mode, "provider_keys": provider_count, "mcp_credentials":mcp_count });
    audit(
        &tx,
        a,
        "security.kms.delete",
        Some(summary(&c)),
        Some(result.clone()),
    )
    .await?;
    tx.commit().await?;
    v.invalidate(&a.tenant_id);
    if let Some(cache) = &state.entitlements {
        cache.invalidate(*a.tenant_id.as_uuid()).await;
    }
    crate::mcp_inspection::evict(*a.tenant_id.as_uuid());
    Ok(result)
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use tower::ServiceExt as _;
    fn claims(
        method: crate::auth::AuthMethod,
        role: Option<crate::auth::Role>,
    ) -> crate::auth::Claims {
        crate::auth::Claims {
            role,
            ..crate::auth::dev_stub_claims(method)
        }
    }
    fn calls() -> Vec<(Method, &'static str, Value)> {
        vec![
            (
                Method::PUT,
                "/v1/security/kms",
                json!({"backend":"vault_transit","key_ref":"key","params":{"url":"https://vault.example.com","mount":"transit"},"secret":"unit-test-token"}),
            ),
            (
                Method::POST,
                "/v1/security/kms/migrate",
                json!({"confirm":true}),
            ),
            (
                Method::POST,
                "/v1/security/kms/rewrap",
                json!({"key_ref":"rotated"}),
            ),
            (
                Method::DELETE,
                "/v1/security/kms",
                json!({"mode":"abandon","confirm":true}),
            ),
        ]
    }
    async fn send(method: Method, path: &str, doc: Value) -> (StatusCode, Value) {
        let state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", "Bearer unit-test")
                    .header("content-type", "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    #[tokio::test]
    async fn every_kms_write_refuses_developer_viewer_and_even_admin_scoped_api_keys() {
        use crate::auth::{AuthMethod, Role};
        for mut who in [
            claims(AuthMethod::JwtBearer, Some(Role::Member)),
            claims(AuthMethod::JwtBearer, Some(Role::Viewer)),
            claims(AuthMethod::ApiKey, None),
        ] {
            who.key_scope = crate::auth::scope::KeyScope::Scoped(
                [crate::auth::scope::Scope::Admin].into_iter().collect(),
            );
            let _claims = crate::auth::test_claims::Guard::set(who);
            for (method, path, doc) in calls() {
                let (status, doc) = send(method, path, doc).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {doc}");
                assert_eq!(doc["error"], "role_forbidden");
                assert_eq!(doc["required_role"], "admin");
            }
        }
    }
    #[tokio::test]
    async fn absent_entitlements_refuse_put_before_any_backend_or_database_call() {
        let _control = crate::control_plane::test_overrides::Guard::new(
            Some(Ok(crate::db::admin_security::AdminAccess::default())),
            None,
            None,
        );
        let _claims = crate::auth::test_claims::Guard::set(claims(
            crate::auth::AuthMethod::JwtBearer,
            Some(crate::auth::Role::Owner),
        ));
        let (method, path, doc) = calls().remove(0);
        let (status, doc) = send(method, path, doc).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(doc["error"], "byok_cmk_required");
    }
    #[tokio::test]
    async fn destructive_confirmation_is_required_before_storage_and_summary_omits_secrets() {
        let _control = crate::control_plane::test_overrides::Guard::new(
            Some(Ok(crate::db::admin_security::AdminAccess::default())),
            None,
            None,
        );
        let _claims = crate::auth::test_claims::Guard::set(claims(
            crate::auth::AuthMethod::JwtBearer,
            Some(crate::auth::Role::Owner),
        ));
        for (method, path, doc) in [
            (
                Method::DELETE,
                "/v1/security/kms",
                json!({"mode":"abandon","confirm":false}),
            ),
            (
                Method::POST,
                "/v1/security/kms/migrate",
                json!({"confirm":false}),
            ),
        ] {
            let (status, doc) = send(method, path, doc).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(doc["error"], "confirmation_required");
        }
        let c = vault::Configuration {
            backend: Backend {
                config: Config::VaultTransit(super::super::backend::Vault {
                    url: "https://vault.example.com".into(),
                    mount: "transit".into(),
                    role_id: None,
                }),
                key_ref: "key".into(),
                secret: Some(SecretString::from("DO-NOT-LEAK-TOKEN")),
            },
            id: Uuid::new_v4(),
            wrapped: b"DO-NOT-LEAK-WRAPPED-DEK".to_vec(),
            revision: 0,
        };
        let text = summary(&c).to_string();
        assert!(!text.contains("DO-NOT-LEAK"));
        assert!(!text.contains("secret"));
        assert!(!text.contains("wrapped"));
    }
}

#[cfg(test)]
mod pg_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    #[tokio::test]
    #[ignore = "operator-run disposable Postgres only; fixture applies migrations, forbidden in W5"]
    async fn og37_pg_migrate_rolls_back_mid_row_and_audit_failure_and_preserves_other_tenant() {
        let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
        let mut client = pool.get().await.unwrap();
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let b = TenantId::from_jwt_claim(Uuid::new_v4());
        let master =
            crate::byok::ByokMasterKey::from_values(Some(&B64.encode([3; 32])), None, None)
                .unwrap()
                .unwrap();
        let dek = [7; 32];
        let id = Uuid::new_v4();
        for tenant in [&a, &b] {
            client
                .execute(
                    "INSERT INTO tenants (id,workos_org_id,name) VALUES ($1,$2,'kms test')",
                    &[tenant.as_uuid(), &format!("org_kms_{tenant}")],
                )
                .await
                .unwrap();
            for provider in ["anthropic", "openai"] {
                let aad = crate::byok::provider_key_aad(tenant, provider);
                let blob = master
                    .encrypt_with_context(&SecretString::from("unit-provider-secret"), &aad)
                    .unwrap();
                client.execute("INSERT INTO provider_keys (tenant_id,provider_id,ciphertext_b64,last4) VALUES ($1,$2,$3,'test')",&[tenant.as_uuid(),&provider,&blob]).await.unwrap();
            }
        }
        async fn blobs(c: &impl tokio_postgres::GenericClient, t: &TenantId) -> Vec<String> {
            c.query(
                "SELECT ciphertext_b64 FROM provider_keys WHERE tenant_id=$1 ORDER BY provider_id",
                &[t.as_uuid()],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get(0))
            .collect()
        }
        let original = blobs(&**client, &a).await;
        let other = blobs(&**client, &b).await;
        // First row changes, second row is corrupt: returning Err must roll back both.
        {
            let tx = client.transaction().await.unwrap();
            tx.execute("UPDATE provider_keys SET ciphertext_b64='corrupt' WHERE tenant_id=$1 AND provider_id='openai'",&[a.as_uuid()]).await.unwrap();
            assert!(migrate_keys(&tx, &a, &master, id, &dek).await.is_err());
            tx.rollback().await.unwrap();
        }
        assert_eq!(blobs(&**client, &a).await, original);
        client.batch_execute("ALTER TABLE admin_audit_log ADD CONSTRAINT og37_refuse CHECK (action <> 'security.kms.migrate') NOT VALID").await.unwrap();
        let actor = crate::db::control_audit::Actor {
            sub: "unit-admin".into(),
            role: "admin",
            auth_method: "workos_session",
            request_id: Uuid::new_v4().to_string(),
            ip: None,
            user_agent: None,
        };
        {
            let tx = client.transaction().await.unwrap();
            assert_eq!(
                migrate_keys(&tx, &a, &master, id, &dek)
                    .await
                    .unwrap_or_else(|_| panic!("migrate")),
                2
            );
            assert!(
                crate::db::control_audit::record(
                    &tx,
                    &a,
                    &actor,
                    crate::db::control_audit::Change {
                        action: "security.kms.migrate",
                        target_type: "tenant_kms",
                        target_id: a.to_string(),
                        before: None,
                        after: Some(json!({"migrated":2}))
                    }
                )
                .await
                .is_err()
            );
            tx.rollback().await.unwrap();
        }
        assert_eq!(blobs(&**client, &a).await, original);
        assert_eq!(blobs(&**client, &b).await, other);
        client
            .batch_execute("ALTER TABLE admin_audit_log DROP CONSTRAINT og37_refuse")
            .await
            .unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            migrate_keys(&tx, &a, &master, id, &dek)
                .await
                .unwrap_or_else(|_| panic!("migrate")),
            2
        );
        crate::db::control_audit::record(
            &tx,
            &a,
            &actor,
            crate::db::control_audit::Change {
                action: "security.kms.migrate",
                target_type: "tenant_kms",
                target_id: a.to_string(),
                before: None,
                after: Some(json!({"migrated":2})),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert!(
            blobs(&**client, &a)
                .await
                .iter()
                .all(|s| crate::byok::ByokMasterKey::is_customer_envelope(s))
        );
        assert_eq!(blobs(&**client, &b).await, other);
        let count:i64=client.query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1 AND action='security.kms.migrate'",&[a.as_uuid()]).await.unwrap().get(0);
        assert_eq!(count, 1);
        let before_rotate = blobs(&**client, &a).await;
        let report = crate::byok_rotate::rotate(&pool, &master, false)
            .await
            .unwrap();
        let providers = report
            .tables
            .iter()
            .find(|t| t.table == "provider_keys")
            .unwrap();
        assert_eq!(providers.customer_managed, 2);
        assert!(report.render().contains("customer_managed_skipped=2"));
        assert_eq!(blobs(&**client, &a).await, before_rotate);
    }
}

#[cfg(test)]
mod mcp_lifecycle_tests {
    use super::*;
    use secrecy::ExposeSecret;
    #[tokio::test]
    #[ignore = "requires disposable local Postgres"]
    async fn mcp_credentials_migrate_with_customer_key_and_preserve_other_tenant() {
        use base64::Engine;
        let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
        let mut client = pool.get().await.unwrap();
        let master = crate::byok::ByokMasterKey::from_values(
            Some(&base64::engine::general_purpose::STANDARD.encode([3; 32])),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let b = TenantId::from_jwt_claim(Uuid::new_v4());
        let server = Uuid::new_v4();
        let other = Uuid::new_v4();
        for (tenant, id) in [(&a, server), (&b, other)] {
            client
                .execute(
                    "INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'MCP lifecycle')",
                    &[tenant.as_uuid(), &format!("org_{tenant}")],
                )
                .await
                .unwrap();
            let purpose = format!("mcp-server-credential:{id}");
            let blob = master
                .encrypt_with_context(
                    &SecretString::from("mcp-test-secret"),
                    &crate::byok::provider_key_aad(tenant, &purpose),
                )
                .unwrap();
            client.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode,credential_kind,credential_ct) VALUES($1,$2,'test','Test','https://example.com','streamable_http','gateway_held','bearer',$3)",&[&id,tenant.as_uuid(),&blob]).await.unwrap();
        }
        let other_blob: String = client
            .query_one(
                "SELECT credential_ct FROM mcp_servers WHERE tenant_id=$1 AND id=$2",
                &[b.as_uuid(), &other],
            )
            .await
            .unwrap()
            .get(0);
        let id = Uuid::new_v4();
        let dek = [9; 32];
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            migrate_keys(&tx, &a, &master, id, &dek)
                .await
                .unwrap_or_else(|_| panic!("migration failed")),
            1,
            "MCP envelopes are a KMS lifecycle consumer"
        );
        tx.commit().await.unwrap();
        let migrated: String = client
            .query_one(
                "SELECT credential_ct FROM mcp_servers WHERE tenant_id=$1 AND id=$2",
                &[a.as_uuid(), &server],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            super::super::open(
                &a,
                &format!("mcp-server-credential:{server}"),
                id,
                &dek,
                &migrated
            )
            .unwrap()
            .expose_secret(),
            "mcp-test-secret"
        );
        assert_eq!(
            client
                .query_one(
                    "SELECT credential_ct FROM mcp_servers WHERE tenant_id=$1 AND id=$2",
                    &[b.as_uuid(), &other]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            other_blob
        );
        let rotated = crate::byok_rotate::rotate(&pool, &master, false)
            .await
            .unwrap();
        assert_eq!(
            rotated
                .tables
                .iter()
                .find(|t| t.table == "mcp_servers")
                .unwrap()
                .customer_managed,
            1
        );
    }
}

#[cfg(all(test, debug_assertions))]
mod mcp_kms_lifecycle_security_tests {
    use super::*;
    use crate::kms::backend::scripted::{SCRIPT, Script};
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use secrecy::ExposeSecret as _;
    use std::{
        cell::RefCell,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tower::ServiceExt as _;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    /// A local Vault transit double. Wrapping preserves the submitted bound DEK
    /// so production's random-DEK roundtrip and tenant/UUID checks remain real.
    fn transit_script(denied: Arc<AtomicBool>) -> Script {
        Script {
            responder: Some(Arc::new(move |request| {
                if denied.load(Ordering::SeqCst) {
                    return Err(KmsError::Denied);
                }
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let key = request.url.rsplit('/').next().unwrap();
                let value = if request.url.contains("/encrypt/") {
                    let plaintext = body["plaintext"].as_str().unwrap();
                    json!({"data":{"ciphertext":format!("vault:test:{key}:{plaintext}")}})
                } else {
                    assert!(request.url.contains("/decrypt/"));
                    let ciphertext = body["ciphertext"].as_str().unwrap();
                    let prefix = format!("vault:test:{key}:");
                    let plaintext = ciphertext.strip_prefix(&prefix).ok_or(KmsError::Denied)?;
                    json!({"data":{"plaintext":plaintext}})
                };
                serde_json::to_vec(&value).map_err(|_| KmsError::Unavailable)
            })),
            ..Script::default()
        }
    }

    struct Fixture {
        pool: crate::db::DbPool,
        state: AppState,
        a: TenantId,
        b: TenantId,
        upstream: MockServer,
    }

    impl Fixture {
        async fn new() -> Self {
            crate::mcp_security_tests::init_master_for_security_tests();
            // The fingerprint key is process-global and set at boot in production; without
            // this the tests passed only when an earlier test had installed it.
            crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
            let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
            let a = TenantId::from_jwt_claim(Uuid::new_v4());
            let b = TenantId::from_jwt_claim(Uuid::new_v4());
            let upstream = MockServer::start().await;
            Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"executed"}]}}))).mount(&upstream).await;
            let c = pool.get().await.unwrap();
            for tenant in [&a, &b] {
                c.execute(
                    "INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'MCP KMS security')",
                    &[tenant.as_uuid(), &format!("org_{tenant}")],
                )
                .await
                .unwrap();
                let server = Uuid::new_v4();
                let aad = crate::byok::provider_key_aad(
                    tenant,
                    &format!("mcp-server-credential:{server}"),
                );
                let blob = crate::byok::master_key()
                    .unwrap()
                    .encrypt_with_context(&SecretString::from("mcp-lifecycle-test-secret"), &aad)
                    .unwrap();
                c.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode,credential_ct,credential_last4) VALUES($1,$2,'lifecycle','Lifecycle',$3,'streamable_http','gateway_held',$4,'cret')", &[&server,tenant.as_uuid(),&upstream.uri(),&blob]).await.unwrap();
            }
            drop(c);
            let source = pool.clone();
            let mut state = crate::handler_harness::test_state(
                crate::providers::ProviderRegistry::new().unwrap(),
            );
            state.pg = Some(pool.clone());
            state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
                Arc::new(move |tenant| {
                    let source = source.clone();
                    Box::pin(async move {
                        let client = source.get().await?;
                        let mut ent = crate::entitlement_cache::ResolvedEntitlements::deny_all();
                        ent.f_customer_kms = true;
                        ent.mcp = Some(crate::mcp_store::load(&client, &tenant).await?);
                        Ok(ent)
                    })
                }),
            )));
            Self {
                pool,
                state,
                a,
                b,
                upstream,
            }
        }

        fn claims(tenant: &TenantId) -> crate::auth::Claims {
            crate::auth::Claims {
                tenant_id: tenant.clone(),
                sub: format!("kms-review:{tenant}"),
                key_scope: crate::auth::scope::KeyScope::from_column(Some(&["mcp".into()])),
                ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
            }
        }

        async fn control(
            &self,
            tenant: &TenantId,
            method: Method,
            path: &str,
            body: Value,
        ) -> (StatusCode, Value) {
            let _claims = crate::auth::test_claims::Guard::set(Self::claims(tenant));
            let _access = crate::control_plane::test_overrides::Guard::new(
                Some(Ok(Default::default())),
                Some(Ok(true)),
                None,
            );
            let response = router(self.state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("authorization", "Bearer test-token")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        }

        async fn configure(&self, tenant: &TenantId, key: &str) -> (StatusCode, Value) {
            self.control(tenant,Method::PUT,"/v1/security/kms",json!({"backend":"vault_transit","key_ref":key,"params":{"url":"https://127.0.0.1","mount":"transit"},"secret":"unit-transit-token"})).await
        }

        async fn adopt(&self, tenant: &TenantId, key: &str) {
            let configured = self.configure(tenant, key).await;
            assert_eq!(
                configured.0,
                StatusCode::OK,
                "configure failed: {}",
                configured.1
            );
            let migrated = self
                .control(
                    tenant,
                    Method::POST,
                    "/v1/security/kms/migrate",
                    json!({"confirm":true}),
                )
                .await;
            assert_eq!(migrated.0, StatusCode::OK, "migrate failed: {}", migrated.1);
            assert_eq!(migrated.1["migrated"], 1);
            self.prove_credential(tenant).await;
        }

        async fn rows(&self, tenant: &TenantId) -> Value {
            let c = self.pool.get().await.unwrap();
            let server: Value = c
                .query_one(
                    "SELECT to_jsonb(s) FROM mcp_servers s WHERE tenant_id=$1",
                    &[tenant.as_uuid()],
                )
                .await
                .unwrap()
                .get(0);
            let config: Option<Value> = c
                .query_opt(
                    "SELECT to_jsonb(k) FROM tenant_kms_configs k WHERE tenant_id=$1",
                    &[tenant.as_uuid()],
                )
                .await
                .unwrap()
                .map(|r| r.get(0));
            let keys: Vec<Value> = c
                .query(
                    "SELECT to_jsonb(k) FROM tenant_data_keys k WHERE tenant_id=$1 ORDER BY id",
                    &[tenant.as_uuid()],
                )
                .await
                .unwrap()
                .iter()
                .map(|r| r.get(0))
                .collect();
            json!({"server":server,"configuration":config,"keys":keys})
        }

        async fn prove_credential(&self, tenant: &TenantId) {
            let c = self.pool.get().await.unwrap();
            let snapshot = crate::mcp_store::load(&c, tenant.as_uuid()).await.unwrap();
            let server = snapshot
                .servers
                .iter()
                .find(|s| s.slug == "lifecycle")
                .unwrap();
            let secret = crate::mcp_proxy::credential(&snapshot, server, tenant, &HeaderMap::new())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                secret.expose_secret(),
                "mcp-lifecycle-test-secret",
                "fresh persisted configuration must open the credential"
            );
            // Also exercise the real warm entitlement reader: never manually evict it
            // here, since a lifecycle write must refresh its MCP consumers itself.
            let (status, body) = self.proxy(tenant).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "warm MCP dispatch after KMS change: {body}"
            );
            assert_eq!(body["result"]["content"][0]["text"], "executed");
            let requests = self.upstream.received_requests().await.unwrap();
            assert_eq!(
                requests.last().unwrap().headers["authorization"],
                "Bearer mcp-lifecycle-test-secret"
            );
        }

        async fn proxy(&self, tenant: &TenantId) -> (StatusCode, Value) {
            let _claims = crate::auth::test_claims::Guard::set(Self::claims(tenant));
            let response = crate::mcp_proxy::router(self.state.clone()).oneshot(Request::builder().method(Method::POST).uri("/v1/mcp/lifecycle").header("authorization","Bearer test-token").header("content-type","application/json").body(Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}).to_string())).unwrap()).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        }

        async fn block_audit(&self, action: Option<&str>) {
            let c = self.pool.get().await.unwrap();
            c.batch_execute("ALTER TABLE admin_audit_log DROP CONSTRAINT IF EXISTS security_kms_lifecycle_audit").await.unwrap();
            if let Some(action) = action {
                assert!(["security.kms.set", "security.kms.delete"].contains(&action));
                c.batch_execute(match action {"security.kms.set"=>"ALTER TABLE admin_audit_log ADD CONSTRAINT security_kms_lifecycle_audit CHECK(action <> 'security.kms.set') NOT VALID","security.kms.delete"=>"ALTER TABLE admin_audit_log ADD CONSTRAINT security_kms_lifecycle_audit CHECK(action <> 'security.kms.delete') NOT VALID",_=>panic!("unknown fixture action")}).await.unwrap();
            }
        }

        async fn audit_count(&self, tenant: &TenantId, action: &str) -> i64 {
            self.pool.get().await.unwrap().query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1 AND action=$2",&[tenant.as_uuid(),&action]).await.unwrap().get(0)
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable local Postgres; scripted local Vault"]
    async fn mcp_kms_configuration_replacement_and_rewrap_preserve_credentials_and_other_tenant() {
        let _loopback = crate::handler_harness::LoopbackBypassGuard::new();
        let denied = Arc::new(AtomicBool::new(false));
        SCRIPT
            .scope(RefCell::new(transit_script(denied)), async {
                let f = Fixture::new().await;
                f.adopt(&f.b, "tenant-b").await;
                f.adopt(&f.a, "original").await;
                let before = f.rows(&f.a).await;
                let other = f.rows(&f.b).await;
                f.block_audit(Some("security.kms.set")).await;
                assert_eq!(
                    f.configure(&f.a, "replacement").await.0,
                    StatusCode::SERVICE_UNAVAILABLE
                );
                assert_eq!(
                    f.rows(&f.a).await,
                    before,
                    "failed audit must roll back configuration, DEK and ciphertext together"
                );
                f.prove_credential(&f.a).await;
                f.block_audit(None).await;
                let replaced = f.configure(&f.a, "replacement").await;
                assert_eq!(replaced.0, StatusCode::OK, "replacement: {}", replaced.1);
                let after = f.rows(&f.a).await;
                assert_ne!(
                    after["server"]["credential_ct"],
                    before["server"]["credential_ct"]
                );
                assert_eq!(after["configuration"]["key_ref"], "replacement");
                let active: Vec<_> = after["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|k| k["retired_at"].is_null())
                    .collect();
                assert_eq!(active.len(), 1);
                assert_eq!(active[0]["id"], replaced.1["dek_id"]);
                assert_ne!(active[0]["id"], before["keys"][0]["id"]);
                f.prove_credential(&f.a).await;
                assert_eq!(f.rows(&f.b).await, other);
                let rewrapped = f
                    .control(
                        &f.a,
                        Method::POST,
                        "/v1/security/kms/rewrap",
                        json!({"key_ref":"rewrapped"}),
                    )
                    .await;
                assert_eq!(rewrapped.0, StatusCode::OK, "rewrap: {}", rewrapped.1);
                let final_rows = f.rows(&f.a).await;
                assert_eq!(
                    final_rows["server"]["credential_ct"], after["server"]["credential_ct"],
                    "rewrap changes the wrapped DEK, not provider envelopes"
                );
                assert_eq!(rewrapped.1["dek_id"], replaced.1["dek_id"]);
                assert_eq!(final_rows["configuration"]["key_ref"], "rewrapped");
                f.prove_credential(&f.a).await;
                f.prove_credential(&f.b).await;
                assert_eq!(f.rows(&f.b).await, other);
                assert_eq!(f.audit_count(&f.a, "security.kms.set").await, 2);
                assert_eq!(f.audit_count(&f.a, "security.kms.rewrap").await, 1);
            })
            .await;
    }

    #[tokio::test]
    #[ignore = "requires disposable local Postgres; scripted local Vault"]
    async fn mcp_kms_unseal_preserves_working_credentials_and_rolls_back_failed_audit() {
        let _loopback = crate::handler_harness::LoopbackBypassGuard::new();
        SCRIPT
            .scope(
                RefCell::new(transit_script(Arc::new(AtomicBool::new(false)))),
                async {
                    let f = Fixture::new().await;
                    f.adopt(&f.b, "tenant-b").await;
                    f.adopt(&f.a, "unseal").await;
                    let before = f.rows(&f.a).await;
                    let other = f.rows(&f.b).await;
                    f.block_audit(Some("security.kms.delete")).await;
                    let failed = f
                        .control(
                            &f.a,
                            Method::DELETE,
                            "/v1/security/kms",
                            json!({"mode":"unseal","confirm":true}),
                        )
                        .await;
                    assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(f.rows(&f.a).await, before);
                    f.prove_credential(&f.a).await;
                    f.block_audit(None).await;
                    let unsealed = f
                        .control(
                            &f.a,
                            Method::DELETE,
                            "/v1/security/kms",
                            json!({"mode":"unseal","confirm":true}),
                        )
                        .await;
                    assert_eq!(unsealed.0, StatusCode::OK, "unseal: {}", unsealed.1);
                    let after = f.rows(&f.a).await;
                    assert!(after["configuration"].is_null());
                    assert_eq!(after["keys"], json!([]));
                    assert_eq!(after["server"]["enabled"], true);
                    assert_eq!(after["server"]["auth_mode"], "gateway_held");
                    let blob = after["server"]["credential_ct"].as_str().unwrap();
                    assert!(crate::byok::ByokMasterKey::kek_id_of(blob).is_some());
                    let server = after["server"]["id"].as_str().unwrap();
                    let aad = crate::byok::provider_key_aad(
                        &f.a,
                        &format!("mcp-server-credential:{server}"),
                    );
                    assert_eq!(
                        crate::byok::master_key()
                            .unwrap()
                            .decrypt_with_context(blob, &aad)
                            .unwrap()
                            .expose_secret(),
                        "mcp-lifecycle-test-secret"
                    );
                    f.prove_credential(&f.a).await;
                    f.prove_credential(&f.b).await;
                    assert_eq!(f.rows(&f.b).await, other);
                    assert_eq!(f.audit_count(&f.a, "security.kms.delete").await, 1);
                },
            )
            .await;
    }

    #[tokio::test]
    #[ignore = "requires disposable local Postgres; scripted local Vault"]
    async fn mcp_kms_abandon_clears_credentials_disables_server_without_kms_and_preserves_other_tenant()
     {
        let _loopback = crate::handler_harness::LoopbackBypassGuard::new();
        let denied = Arc::new(AtomicBool::new(false));
        SCRIPT
            .scope(RefCell::new(transit_script(denied.clone())), async {
                let f = Fixture::new().await;
                f.adopt(&f.b, "tenant-b").await;
                f.adopt(&f.a, "abandon").await;
                let before = f.rows(&f.a).await;
                let other = f.rows(&f.b).await;
                denied.store(true, Ordering::SeqCst);
                let kms_before = SCRIPT.with(|s| s.borrow().requests.len());
                f.block_audit(Some("security.kms.delete")).await;
                assert_eq!(
                    f.control(
                        &f.a,
                        Method::DELETE,
                        "/v1/security/kms",
                        json!({"mode":"abandon","confirm":true})
                    )
                    .await
                    .0,
                    StatusCode::SERVICE_UNAVAILABLE
                );
                assert_eq!(
                    f.rows(&f.a).await,
                    before,
                    "audit failure must restore the credential and enabled state"
                );
                f.block_audit(None).await;
                let abandoned = f
                    .control(
                        &f.a,
                        Method::DELETE,
                        "/v1/security/kms",
                        json!({"mode":"abandon","confirm":true}),
                    )
                    .await;
                assert_eq!(
                    abandoned.0,
                    StatusCode::OK,
                    "abandon must work with inaccessible customer KMS: {}",
                    abandoned.1
                );
                assert_eq!(
                    SCRIPT.with(|s| s.borrow().requests.len()),
                    kms_before,
                    "abandon must not contact KMS"
                );
                let after = f.rows(&f.a).await;
                assert!(after["configuration"].is_null());
                assert_eq!(after["keys"], json!([]));
                assert!(after["server"]["credential_ct"].is_null());
                assert!(after["server"]["credential_last4"].is_null());
                assert_eq!(after["server"]["auth_mode"], "none");
                assert_eq!(after["server"]["enabled"], false);
                let upstream_before = f.upstream.received_requests().await.unwrap().len();
                let refused = f.proxy(&f.a).await;
                assert_eq!(refused.0, StatusCode::FORBIDDEN);
                assert_eq!(refused.1["error"], "mcp_server_disabled");
                assert_eq!(
                    f.upstream.received_requests().await.unwrap().len(),
                    upstream_before
                );
                denied.store(false, Ordering::SeqCst);
                f.prove_credential(&f.b).await;
                assert_eq!(f.rows(&f.b).await, other);
                assert_eq!(f.audit_count(&f.a, "security.kms.delete").await, 1);
            })
            .await;
    }
}
