//! Tenant-registered JWT principal boundary. Raw subjects stay in secret custody.
use super::*;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use tracelane_audit_verifier::action::Principal;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub issuer: String,
    pub jwks_url: String,
    pub audience: String,
    pub allowed_algs: Vec<Algorithm>,
}
pub struct Verified {
    tenant: Uuid,
    registration: Uuid,
    issuer: String,
    subject: SecretString,
    roles: Vec<String>,
    issued: i64,
    not_before: Option<i64>,
    expires: i64,
}
impl Verified {
    pub fn minimize(&self, secret: &SecretString) -> Result<Principal> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose_secret().as_bytes());
        let mut context = hmac::Context::with_key(&key);
        context.update(b"tracelane.principal-subject.v1\0");
        context.update(&(self.issuer.len() as u64).to_be_bytes());
        context.update(self.issuer.as_bytes());
        context.update(self.subject.expose_secret().as_bytes());
        let p = Principal {
            iss: self.issuer.clone(),
            sub_digest: hex::encode(context.sign().as_ref()),
            roles: self.roles.clone(),
        };
        p.validate()?;
        Ok(p)
    }
}
fn allowed(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::EdDSA
    )
}
fn limits() -> Result<&'static crate::mcp_policy::PrincipalLimits> {
    Ok(&crate::mcp_policy::settings()?.principal)
}
fn deserialize_subject<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<SecretString, D::Error> {
    String::deserialize(d).map(SecretString::from)
}
#[derive(Deserialize)]
struct TokenClaims {
    iss: String,
    #[serde(deserialize_with = "deserialize_subject")]
    sub: SecretString,
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
    #[serde(default)]
    roles: Vec<String>,
}
fn verify_jwks(
    token: &str,
    issuer: &Issuer,
    tenant: Uuid,
    registration: Uuid,
    jwks: &Value,
    now: i64,
) -> Result<Verified> {
    let cap = limits()?;
    ensure!(token.len() <= cap.max_token_bytes, "principal_invalid");
    let header = jsonwebtoken::decode_header(token).context("principal_invalid")?;
    ensure!(
        allowed(header.alg) && issuer.allowed_algs.contains(&header.alg),
        "principal_invalid"
    );
    let kid = header
        .kid
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= cap.max_claim_chars)
        .context("principal_invalid")?;
    let keys = jwks["keys"].as_array().context("principal_invalid")?;
    let mut matching = keys.iter().filter(|k| k["kid"].as_str() == Some(kid));
    let key = matching.next().context("principal_invalid")?;
    ensure!(matching.next().is_none(), "principal_invalid");
    ensure!(
        key.get("use").is_none_or(|u| u == "sig"),
        "principal_invalid"
    );
    ensure!(
        key.get("key_ops").is_none_or(|v| v
            .as_array()
            .is_some_and(|a| a.iter().any(|op| op == "verify"))),
        "principal_invalid"
    );
    ensure!(
        key.get("alg").is_none_or(
            |a| serde_json::from_value::<Algorithm>(a.clone()).is_ok_and(|a| a == header.alg)
        ),
        "principal_invalid"
    );
    let key_type_matches = match header.alg {
        Algorithm::ES256 => key["kty"] == "EC" && key["crv"] == "P-256",
        Algorithm::EdDSA => key["kty"] == "OKP" && key["crv"] == "Ed25519",
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => key["kty"] == "RSA",
        _ => false,
    };
    ensure!(key_type_matches, "principal_invalid");
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(key.clone()).context("principal_invalid")?;
    let key = DecodingKey::from_jwk(&jwk).context("principal_invalid")?;
    // Header selection is intersected with the fixed asymmetric allowlist AND registration.
    let alg = match header.alg {
        Algorithm::RS256 => Algorithm::RS256,
        Algorithm::RS384 => Algorithm::RS384,
        Algorithm::RS512 => Algorithm::RS512,
        Algorithm::ES256 => Algorithm::ES256,
        Algorithm::EdDSA => Algorithm::EdDSA,
        _ => anyhow::bail!("principal_invalid"),
    };
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&issuer.issuer]);
    validation.set_audience(&[&issuer.audience]);
    validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp"]);
    // Use the caller's explicit clock; reserve_tx checks the database clock again.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    let claims = jsonwebtoken::decode::<TokenClaims>(token, &key, &validation)
        .context("principal_invalid")?
        .claims;
    validate_times(claims.iat, claims.nbf, claims.exp, now)?;
    ensure!(
        !claims.sub.expose_secret().is_empty()
            && claims.sub.expose_secret().len() <= cap.max_claim_chars
            && !claims.sub.expose_secret().chars().any(char::is_control),
        "principal_invalid"
    );
    ensure!(
        claims.roles.len() <= cap.max_roles
            && claims.roles.iter().all(|r| !r.is_empty()
                && r.len() <= cap.max_claim_chars
                && r.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))),
        "principal_invalid"
    );
    let mut roles = claims.roles;
    roles.sort();
    roles.dedup();
    Ok(Verified {
        tenant,
        registration,
        issuer: claims.iss,
        subject: claims.sub,
        roles,
        issued: claims.iat,
        not_before: claims.nbf,
        expires: claims.exp,
    })
}
#[cfg(test)]
#[path = "principal_tests.rs"]
mod tests;

/// The transport carries an opaque credential; callers cannot construct a Verified value.
pub enum Input {
    Missing,
    Invalid,
    Unverifiable,
    Verified(Verified),
}
fn control_plane_issuer() -> Result<reqwest::Url> {
    let raw = std::env::var("WORKOS_ISSUER").context("principal_unverifiable")?;
    let url = reqwest::Url::parse(&raw).context("principal_unverifiable")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "principal_unverifiable"
    );
    Ok(url)
}
fn validate_times(issued: i64, not_before: Option<i64>, expires: i64, now: i64) -> Result<()> {
    let cap = limits()?;
    let latest = now
        .checked_add(cap.clock_skew_secs)
        .context("principal_invalid")?;
    ensure!(
        issued <= latest
            && not_before.is_none_or(|t| t <= latest)
            && expires > now
            && expires > issued
            && expires
                .checked_sub(issued)
                .is_some_and(|d| d <= cap.max_lifetime_secs),
        "principal_invalid"
    );
    Ok(())
}

pub fn validate_issuer(issuer: &Issuer) -> Result<()> {
    let cap = limits()?;
    for raw in [&issuer.issuer, &issuer.jwks_url] {
        ensure!(
            raw.len() <= crate::mcp_policy::settings()?.limits.max_url_bytes,
            "principal_invalid"
        );
        let url = reqwest::Url::parse(raw).context("principal_invalid")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "principal_invalid"
        );
    }
    // The verifier requires a literal lowercase `https://` prefix and no control characters; a
    // registration the URL parser normalises past either could never verify (Low-3, 2026-11-15).
    ensure!(
        issuer.issuer.starts_with("https://") && !issuer.issuer.chars().any(char::is_control),
        "principal_invalid"
    );
    // The shared control-plane issuer cannot provide tenant-scoped principal roles.
    // URL comparison closes spelling aliases; signed JWT issuer matching stays exact.
    if let Ok(control) = control_plane_issuer() {
        ensure!(
            reqwest::Url::parse(&issuer.issuer)? != control,
            "principal_invalid"
        );
    }
    // Nor under ANOTHER issuer spelling (a custom auth domain, a WorkOS URL change): the control
    // plane's audience and JWKS identify its tokens whatever `iss` they carry (re-review M-1).
    // Fail-CLOSED: with a control plane configured, an unknown control audience cannot
    // establish the exclusion boundary. WorkOS tokens may carry the client id as `aud`
    // under a different `iss`, so both values are refused as a tenant audience.
    if std::env::var("WORKOS_CLIENT_ID").is_ok() {
        ensure!(
            std::env::var("WORKOS_AUDIENCE").is_ok(),
            "principal_unverifiable"
        );
    }
    for control in ["WORKOS_AUDIENCE", "WORKOS_CLIENT_ID"] {
        if let Ok(audience) = std::env::var(control) {
            ensure!(issuer.audience != audience, "principal_invalid");
        }
    }
    // URL equality is only a cheap first line (percent-encoding, trailing dots and custom
    // domains alias it); `fetch_keys` refuses by key identity as well.
    if let Some(control_jwks) = crate::auth::jwks::control_plane_jwks_url() {
        let control_jwks = reqwest::Url::parse(&control_jwks).context("principal_unverifiable")?;
        ensure!(
            reqwest::Url::parse(&issuer.jwks_url)? != control_jwks,
            "principal_invalid"
        );
    }
    ensure!(
        !issuer.audience.is_empty()
            && issuer.audience.len() <= cap.max_claim_chars
            && !issuer.audience.chars().any(char::is_control),
        "principal_invalid"
    );
    ensure!(
        !issuer.allowed_algs.is_empty() && issuer.allowed_algs.iter().all(|a| allowed(*a)),
        "principal_invalid"
    );
    Ok(())
}
struct CachedKeys {
    keys: Option<Value>,
    loaded: std::time::Instant,
    last_attempt: Option<std::time::Instant>,
}
type CacheEntry = std::sync::Arc<tokio::sync::Mutex<CachedKeys>>;
struct Cache {
    entries: std::sync::Mutex<BTreeMap<(Uuid, Uuid), CacheEntry>>,
    capacity: usize,
}
impl Cache {
    fn entry(&self, id: (Uuid, Uuid), ttl: std::time::Duration) -> Result<CacheEntry> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("principal_unverifiable"))?;
        if let Some(entry) = entries.get(&id) {
            return Ok(entry.clone());
        }
        // Reclaim expired idle entries first. Active users retain their single-flight state.
        if entries.len() >= self.capacity {
            entries.retain(|_, entry| {
                std::sync::Arc::strong_count(entry) > 1
                    || match entry.try_lock() {
                        Ok(keys) => {
                            keys.loaded.elapsed() < ttl
                                || keys.last_attempt.is_some_and(|at| at.elapsed() < ttl)
                        }
                        Err(_) => true,
                    }
            });
        }
        if entries.len() >= self.capacity {
            // Recent idle entries must not exclude other tenants. Eviction may reset
            // their resident-only refresh throttle; MCP tenant/key RPM admission is separate.
            let oldest = entries
                .iter()
                .filter_map(|(id, entry)| {
                    if std::sync::Arc::strong_count(entry) != 1 {
                        return None;
                    }
                    let keys = entry.try_lock().ok()?;
                    Some((
                        *id,
                        keys.last_attempt.unwrap_or(keys.loaded).max(keys.loaded),
                    ))
                })
                .min_by_key(|(_, touched)| *touched)
                .map(|(id, _)| id);
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        ensure!(entries.len() < self.capacity, "principal_unverifiable");
        let entry = std::sync::Arc::new(tokio::sync::Mutex::new(CachedKeys {
            keys: None,
            loaded: std::time::Instant::now(),
            last_attempt: None,
        }));
        entries.insert(id, entry.clone());
        Ok(entry)
    }
}
fn cache() -> Result<&'static Cache> {
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    let capacity = usize::try_from(limits()?.cache_entries)?;
    Ok(CACHE.get_or_init(|| Cache {
        entries: std::sync::Mutex::new(BTreeMap::new()),
        capacity,
    }))
}
async fn fetch_keys(issuer: &Issuer) -> Result<Value> {
    validate_issuer(issuer)?;
    let target = crate::ssrf_guard::validate_url_pinned(&issuer.jwks_url).await?;
    let client = target
        .pin(crate::ssrf_guard::safe_client_builder().no_proxy())
        .timeout(std::time::Duration::from_millis(
            crate::mcp_policy::settings()?.policy.verify_timeout_ms,
        ))
        .build()?;
    let keys = request_keys(&client, &issuer.jwks_url).await?;
    refuse_control_plane_keys(&keys).await?;
    Ok(keys)
}
/// A tenant key set must not contain any key id the control plane signs with: control-plane
/// tokens carry those `kid`s, so an overlap is the control plane's keys under another URL.
///
/// # Errors
/// Fail-CLOSED: `principal_invalid` on any shared `kid`; `principal_unverifiable` when a
/// control plane is configured but its key set cannot be read.
async fn refuse_control_plane_keys(keys: &Value) -> Result<()> {
    let Some(control) = crate::auth::jwks::control_plane_kids()
        .await
        .context("principal_unverifiable")?
    else {
        return Ok(()); // no control plane configured: no control-plane tokens exist
    };
    ensure!(!shares_control_kid(keys, &control), "principal_invalid");
    Ok(())
}
fn shares_control_kid(keys: &Value, control: &std::collections::HashSet<String>) -> bool {
    keys["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| k["kid"].as_str())
        .any(|kid| control.contains(kid))
}
async fn request_keys(client: &reqwest::Client, url: &str) -> Result<Value> {
    let mut response = client.get(url).send().await.map_err(|e| e.without_url())?;
    ensure!(response.status().is_success(), "principal_unverifiable");
    let cap = limits()?.max_jwks_bytes;
    ensure!(
        response.content_length().is_none_or(|n| n <= cap as u64),
        "principal_unverifiable"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url())? {
        ensure!(
            body.len().saturating_add(chunk.len()) <= cap,
            "principal_unverifiable"
        );
        body.extend_from_slice(&chunk);
    }
    crate::strict_json::from_slice(&body).map_err(|_| anyhow::anyhow!("principal_unverifiable"))
}
async fn cached_keys(
    tenant: Uuid,
    registration: Uuid,
    issuer: &Issuer,
    kid: &str,
) -> Result<Value> {
    cached_keys_with(
        tenant,
        registration,
        kid,
        std::time::Duration::from_secs(limits()?.jwks_ttl_secs),
        || fetch_keys(issuer),
    )
    .await
}
async fn cached_keys_with<F, Fut>(
    tenant: Uuid,
    registration: Uuid,
    kid: &str,
    ttl: std::time::Duration,
    fetch: F,
) -> Result<Value>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let entry = cache()?.entry((tenant, registration), ttl)?;
    let mut entry = entry.lock().await;
    let fresh = entry.keys.is_some() && entry.loaded.elapsed() < ttl;
    let known = entry
        .keys
        .as_ref()
        .and_then(|v| v["keys"].as_array())
        .is_some_and(|a| a.iter().any(|k| k["kid"].as_str() == Some(kid)));
    if fresh && known {
        return entry.keys.clone().context("principal_unverifiable");
    }
    // One attempt per TTL also bounds unknown-kid storms; failed fetches never renew keys.
    ensure!(
        entry.last_attempt.is_none_or(|at| at.elapsed() >= ttl),
        "principal_unverifiable"
    );
    entry.last_attempt = Some(std::time::Instant::now());
    let keys = fetch().await?;
    entry.loaded = std::time::Instant::now();
    entry.keys = Some(keys.clone());
    Ok(keys)
}
#[tracing::instrument(skip_all)]
pub async fn verify_headers(
    pool: &deadpool_postgres::Pool,
    tenant: &TenantId,
    headers: &axum::http::HeaderMap,
) -> Input {
    let mut values = headers.get_all("tracelane-principal").iter();
    let Some(value) = values.next() else {
        return Input::Missing;
    };
    if values.next().is_some() {
        return Input::Invalid;
    }
    let Ok(token) = value.to_str() else {
        return Input::Invalid;
    };
    let Ok(settings) = crate::mcp_policy::settings() else {
        return Input::Unverifiable;
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(settings.policy.verify_timeout_ms),
        verify_registered(pool, tenant, token),
    )
    .await;
    match result {
        Err(_) => Input::Unverifiable,
        Ok(result) => match result {
            Ok(p) => Input::Verified(p),
            Err(e) if e.to_string() == "principal_invalid" => Input::Invalid,
            Err(_) => Input::Unverifiable,
        },
    }
}
async fn verify_registered(
    pool: &deadpool_postgres::Pool,
    tenant: &TenantId,
    token: &str,
) -> Result<Verified> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    // Unknown control-plane issuer identity cannot establish the exclusion boundary.
    // Registration can be prepared without it, but principal admission fails closed.
    control_plane_issuer()?;
    let cap = limits()?;
    ensure!(
        token.len() <= limits()?.max_token_bytes,
        "principal_invalid"
    );
    let header = jsonwebtoken::decode_header(token).context("principal_invalid")?;
    ensure!(allowed(header.alg), "principal_invalid");
    let kid = header
        .kid
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= cap.max_claim_chars)
        .context("principal_invalid")?;
    // Every verify, not only at key fetch: a tenant key set cached before WorkOS published a
    // new key must still not verify a token signed under it (review M-1, 2026-11-15).
    ensure!(
        !crate::auth::jwks::is_control_plane_kid(kid)
            .await
            .context("principal_unverifiable")?,
        "principal_invalid"
    );
    let payload = token.split('.').nth(1).context("principal_invalid")?;
    let decoded = secrecy::zeroize::Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(payload)
            .context("principal_invalid")?,
    );
    #[derive(Deserialize)]
    struct Hint {
        iss: String,
    }
    let hint: Hint = serde_json::from_slice(&decoded).context("principal_invalid")?;
    let issuer = hint.iss.as_str();
    // The unverified issuer is only a tenant-scoped lookup key, never policy evidence.
    let db = pool.get().await?;
    let row = db.query_opt("SELECT id,jwks_url,audience,allowed_algs FROM tenant_principal_issuers WHERE tenant_id=$1 AND issuer=$2", &[tenant.as_uuid(), &issuer]).await?.context("principal_invalid")?;
    let registration: Uuid = row.get(0);
    let algs: Vec<String> = row.get(3);
    let issuer = Issuer {
        issuer: issuer.to_owned(),
        jwks_url: row.get(1),
        audience: row.get(2),
        allowed_algs: algs
            .into_iter()
            .map(|a| serde_json::from_value(json!(a)))
            .collect::<std::result::Result<_, _>>()?,
    };
    drop(db);
    validate_issuer(&issuer)?;
    ensure!(
        issuer.allowed_algs.contains(&header.alg),
        "principal_invalid"
    );
    let keys = cached_keys(*tenant.as_uuid(), registration, &issuer, kid).await?;
    verify_jwks(
        token,
        &issuer,
        *tenant.as_uuid(),
        registration,
        &keys,
        Utc::now().timestamp(),
    )
}
impl Verified {
    pub async fn recheck(&self, tx: &Transaction<'_>, tenant: &TenantId) -> Result<()> {
        let now = db_now(tx).await?.timestamp();
        ensure!(self.tenant == *tenant.as_uuid(), "principal_invalid");
        validate_times(self.issued, self.not_before, self.expires, now)?;
        ensure!(
            tx.query_opt(
                "SELECT 1 FROM tenant_principal_issuers WHERE tenant_id=$1 AND id=$2 FOR SHARE",
                &[tenant.as_uuid(), &self.registration]
            )
            .await?
            .is_some(),
            "principal_invalid"
        );
        Ok(())
    }
    pub fn expires(&self) -> i64 {
        self.expires
    }
}
#[cfg(test)]
pub(super) fn test_issuer() -> Issuer {
    tests::issuer()
}
#[cfg(test)]
pub(super) fn test_set_not_before(verified: &mut Verified, not_before: i64) {
    verified.not_before = Some(not_before);
}

#[cfg(test)]
pub(super) fn test_verified(tenant: Uuid, registration: Uuid, sub: &str, now: i64) -> Verified {
    tests::verified_at(tenant, registration, sub, now)
}

/// Compare only when the verified human session has an explicitly configured issuer
/// equal to the issuer in the signed principal. Other domains have no subject mapping.
pub(super) fn same_subject(
    p: &Principal,
    issuer: Option<&str>,
    sub: &str,
    secret: &SecretString,
) -> Result<bool> {
    p.validate()?;
    if issuer != Some(p.iss.as_str()) {
        return Ok(false);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose_secret().as_bytes());
    let mut context = hmac::Context::with_key(&key);
    context.update(b"tracelane.principal-subject.v1\0");
    context.update(&(p.iss.len() as u64).to_be_bytes());
    context.update(p.iss.as_bytes());
    context.update(sub.as_bytes());
    Ok(p.sub_digest == hex::encode(context.sign().as_ref()))
}
/// WorkOS-only mapping for historical signed evidence: other identity domains have
/// no subject equivalence. New principal admission excludes the shared WorkOS issuer.
/// Fail CLOSED on unavailable or malformed stored evidence; no raw subject is persisted.
#[tracing::instrument(skip_all)]
pub(crate) async fn same_approver_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    action: Uuid,
    digest: &str,
) -> Result<bool> {
    let row = tx.query_opt("SELECT payload::jsonb->'body'->'principal',payload::jsonb->>'schema_version' FROM audit_log_rows WHERE tenant_id=$1 AND event_type='action_proposed' AND payload::jsonb->>'action_id'=$2 AND payload::jsonb->>'request_digest'=$3", &[claims.tenant_id.as_uuid(), &action.to_string(), &digest]).await?;
    let row = row.context("evidence_unavailable")?;
    let version: Option<String> = row.try_get(1)?;
    let version = version.context("evidence_unavailable")?;
    ensure!(
        matches!(version.as_str(), "1" | "2"),
        "evidence_unavailable"
    );
    let Some(value) = row.get::<_, Option<Value>>(0) else {
        ensure!(version == "1", "evidence_unavailable");
        return Ok(false);
    };
    ensure!(version == "2", "evidence_unavailable");
    let principal: Principal = serde_json::from_value(value)?;
    let issuer = std::env::var("WORKOS_ISSUER").ok();
    if issuer.as_deref() != Some(principal.iss.as_str()) {
        return Ok(false);
    }
    let secret = tokenization_secret_tx(
        tx,
        &claims.tenant_id,
        resolved,
        crate::byok::master_key().context("evidence_unavailable")?,
    )
    .await?;
    same_subject(&principal, issuer.as_deref(), &claims.sub, &secret)
}

#[cfg(test)]
pub(super) async fn test_cached_token(tenant: Uuid, registration: Uuid, issuer: &Issuer) -> String {
    test_cached_token_with_claims(tenant, registration, issuer, json!({})).await
}
#[cfg(test)]
pub(super) async fn test_cached_token_with_claims(
    tenant: Uuid,
    registration: Uuid,
    issuer: &Issuer,
    extra: Value,
) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    let random = SystemRandom::new();
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der.as_ref(), &random).unwrap();
    let public = pair.public_key().as_ref();
    let jwks = json!({"keys":[{"kty":"EC","crv":"P-256","kid":"test", "alg":"ES256", "x":URL_SAFE_NO_PAD.encode(&public[1..33]), "y":URL_SAFE_NO_PAD.encode(&public[33..65])}]});
    let entry = cache()
        .unwrap()
        .entry(
            (tenant, registration),
            std::time::Duration::from_secs(limits().unwrap().jwks_ttl_secs),
        )
        .unwrap();
    let mut entry = entry.lock().await;
    entry.keys = Some(jwks);
    entry.loaded = std::time::Instant::now();
    entry.last_attempt = Some(entry.loaded);
    let now = Utc::now().timestamp();
    let mut claims = json!({"iss":issuer.issuer,"aud":issuer.audience,"sub":"synthetic-person","iat":now,"exp":now+300,"roles":["treasury"]});
    claims
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some("test".into());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ec_der(der.as_ref()),
    )
    .unwrap()
}

#[cfg(test)]
mod control_kid_tests {
    use super::shares_control_kid;
    use serde_json::json;
    fn control() -> std::collections::HashSet<String> {
        ["wos-key-1".to_owned()].into_iter().collect()
    }
    #[test]
    fn tenant_key_set_carrying_a_control_plane_kid_is_refused() {
        let keys = json!({"keys":[{"kid":"tenant-a"},{"kid":"wos-key-1"}]});
        assert!(shares_control_kid(&keys, &control()));
    }
    #[test]
    fn tenant_key_set_with_its_own_kids_is_accepted() {
        let keys = json!({"keys":[{"kid":"tenant-a"},{"kid":"tenant-b"}]});
        assert!(!shares_control_kid(&keys, &control()));
    }
    #[test]
    fn key_set_without_keys_array_shares_nothing() {
        assert!(!shares_control_kid(&json!({}), &control()));
        assert!(!shares_control_kid(
            &json!({"keys":[{"n":"x"}]}),
            &control()
        ));
    }
}
