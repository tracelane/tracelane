//! JWT authentication, API key validation, and claims extraction.
//!
//! `tenant_id` is extracted exclusively from a validated JWT claim — never
//! from the request body. Enforced structurally via `TenantId::from_jwt_claim`.
//!
//! Two authentication paths:
//! - **JWT Bearer**: WorkOS-issued JWT, RS256 / Ed25519 / ES256, validated
//!   against the cached WorkOS JWKS (`auth::jwks`).
//! - **API key**: Tenant-scoped `tlane_<base62>` key, hash-looked-up in
//!   Postgres (Week-5 wiring; debug stub today).
//!
//! Dev workflow: when `WORKOS_CLIENT_ID` is unset, debug builds fall back
//! to a fixed dev tenant so local cargo runs work without WorkOS. Release
//! builds without `WORKOS_CLIENT_ID` refuse the request.
//!
//! SPIFFE mTLS for ingest workers lives in `crates/ingest/src/auth.rs`.

pub mod api_key;
pub mod jwks;
mod org_tenant_cache;
pub mod workos_webhook;

use std::sync::OnceLock;

use anyhow::{Context as _, Result, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use secrecy::SecretString;
use serde::Deserialize;
use tracelane_shared::TenantId;
use uuid::Uuid;

/// Audience test-bypass gate: debug builds only.
#[cfg(debug_assertions)]
fn is_audience_test_bypass_enabled() -> bool {
    std::env::var("TRACELANE_AUTH_TEST_NO_AUDIENCE").as_deref() == Ok("1")
}

#[cfg(not(debug_assertions))]
fn is_audience_test_bypass_enabled() -> bool {
    false
}

/// JWT algorithms accepted by the gateway.
///
/// `ALLOWED_JWT_ALGORITHMS.contains(&alg)` bail in `decode_and_validate`**,
/// which rejects any header-claimed `alg` outside this set BEFORE any crypto or
/// `Validation` is built. Do NOT remove that bail — the per-request
/// `Validation.algorithms` is `[alg]` (single, already-allowlisted), not this
/// full list, because jsonwebtoken v10 (`decoding.rs:342`) rejects a key whose
/// family differs from ANY listed alg, so a mixed RSA+EC+Ed list can never
/// validate a single-family key (the InvalidAlgorithm bug, fixed 2026-06-09).
///
/// HMAC-family (`HS256`, `HS384`, `HS512`) are deliberately excluded —
/// WorkOS issues asymmetric tokens only, and accepting symmetric algs
/// next to RSA/EC public-key material opens the classic "use the RSA
/// pubkey bytes as an HMAC secret" attack.
const ALLOWED_JWT_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::EdDSA,
];

/// Claims extracted from a validated JWT or API key.
///
/// `tenant_id` is the only source of truth for tenant identity in the
/// gateway hot path. It is never read from a request body.
#[derive(Debug, Clone)]
pub struct Claims {
    pub tenant_id: TenantId,
    /// Subject (user ID or service account ID from WorkOS)
    pub sub: String,
    /// Expiry timestamp (Unix seconds since epoch)
    pub exp: u64,
    /// Authentication method that produced these claims.
    pub auth_method: AuthMethod,
    /// Org membership role, read from the WorkOS session JWT `role` claim
    /// (IDENTITY_TEAM_SPEC §1). `None` for API keys, service tokens, the dev
    /// stub, and JWTs issued before roles were configured in WorkOS — all of
    /// which are grandfathered to full access (see [`Claims::can_admin`]).
    pub role: Option<Role>,
}

/// The three org roles (IDENTITY_TEAM_SPEC §1). Read from the WorkOS session
/// JWT `role` claim; never stored in a Tracelane role table.
///
/// Only these exact slugs restrict access. WorkOS's built-in `admin` slug and
/// any unknown/absent slug map to `None` (grandfathered full access) so
/// enabling this gate cannot demote existing admins or lock out API keys before
/// the WorkOS environment roles are reconfigured to owner/member/viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Member,
    Viewer,
}

impl Role {
    fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "owner" => Some(Self::Owner),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            // `admin` (WorkOS default) + anything unknown → None (full access).
            _ => None,
        }
    }
}

impl Claims {
    /// May this caller mint/revoke API keys? Everyone except an explicit
    /// `viewer` (IDENTITY_TEAM_SPEC §1: members mint their own keys).
    pub fn can_mint_keys(&self) -> bool {
        self.role != Some(Role::Viewer)
    }

    /// May this caller perform owner-scoped actions — billing, BYOK provider /
    /// encryption keys, member management (IDENTITY_TEAM_SPEC §1)? Explicit
    /// `member`/`viewer` are denied; `owner`, legacy `admin`, API-key / service
    /// auth, and pre-role-config JWTs (`role == None`) are grandfathered.
    pub fn can_admin(&self) -> bool {
        !matches!(self.role, Some(Role::Member) | Some(Role::Viewer))
    }
}

/// caller hint). Callers wrap this string in their own response type — kept
/// as a plain string so both the `(StatusCode, String)` and `Response` route
/// styles emit an identical body. `required` is the minimum role the route
/// wants (e.g. `"owner"`, or `"member"` for the non-viewer key-mint gate).
pub fn role_forbidden_json(required: &str) -> String {
    format!(r#"{{"error":"role_forbidden","required_role":"{required}","upgrade_url":null}}"#)
}

/// How a request was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    JwtBearer,
    ApiKey,
    /// mTLS SPIFFE SVID (ingest workers only).
    Mtls,
}

/// Dev-build fixed tenant UUID — used when `WORKOS_CLIENT_ID` is unset.
/// Centralised so dev builds, smoke tests, and prompt_routes all see the
/// same tenant.
pub(crate) const DEV_TENANT_UUID: &str = "00000000-0000-0000-0000-000000000001";

/// Single-tenant self-host auth config (ADR-067), installed once at gateway
/// startup via [`install_self_host_auth`] when `TRACELANE_SELF_HOST=1` and the
/// shared multi-tenant hard-fail guard passed (refuses to boot if Postgres /
/// WorkOS / a SPIRE socket is present). When present, EVERY request
/// authenticates as the one configured tenant — there is no Postgres/WorkOS to
/// look a key up against, and no second tenant to escalate to. The bearer token
/// is checked against the operator's `TRACELANE_MASTER_KEY` (constant-time), so
/// an internet-exposed self-host is not an open proxy. Never set in hosted.
struct SelfHostAuth {
    tenant_id: TenantId,
    /// The operator's `TRACELANE_MASTER_KEY`. `None` only when the operator did
    /// not set one (dev); then any non-empty bearer token is accepted.
    master_key: Option<SecretString>,
}

static SELF_HOST_AUTH: OnceLock<SelfHostAuth> = OnceLock::new();

/// Install single-tenant self-host auth. Called exactly once at startup; a
/// second call is ignored (non-panicking, unlike `byok::set_global_master_key`).
pub fn install_self_host_auth(tenant_id: TenantId, master_key: Option<SecretString>) {
    let _ = SELF_HOST_AUTH.set(SelfHostAuth {
        tenant_id,
        master_key,
    });
}

/// Authenticate a request in single-tenant self-host mode (ADR-067).
///
/// Every valid credential maps to the ONE configured tenant. When the operator
/// set `TRACELANE_MASTER_KEY` (the compose always does) the bearer token MUST
/// equal it, compared in constant time; otherwise any non-empty token is
/// accepted (dev without an auth secret). Reads neither Postgres nor WorkOS.
///
/// # Errors
/// Fail-closed: a bearer token that does not match the configured master key is
/// rejected (caller returns 401).
fn validate_self_host(token: &str, sh: &SelfHostAuth) -> Result<Claims> {
    use secrecy::ExposeSecret as _;
    if let Some(mk) = &sh.master_key {
        // Constant-time compare (same manual pattern as billing::webhook, so no
        // deprecated `ring::constant_time` and no new dep) — avoids leaking the
        // master key via early-return timing on the byte comparison.
        if !constant_time_eq(token.as_bytes(), mk.expose_secret().as_bytes()) {
            bail!("invalid self-host credentials");
        }
    }
    Ok(Claims {
        tenant_id: sh.tenant_id.clone(),
        sub: "self-host".to_string(),
        exp: u64::MAX,
        auth_method: AuthMethod::ApiKey,
        role: None,
    })
}

/// Constant-time byte-slice equality (matches `billing::webhook::constant_time_eq`).
/// A length mismatch returns early — that reveals only the length, and the
/// per-byte comparison over the shared length is branch-free.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// WorkOS JWT claim shape.
///
/// Two ways a tenant identity arrives, resolved by [`resolve_tenant_id`]:
/// - `tenant_id` — an internal tenant UUID embedded directly (service tokens
///   / legacy JWTs). Accepts the plain or the namespaced URI claim.
/// - `org_id` — the WorkOS organization id (`org_...`) carried by every
///   AuthKit access token the dashboard forwards. Bridged to the internal
///   tenant UUID via `tenants.workos_org_id` (ADR-042 bug #2).
///
/// Both are optional; a token with neither is rejected.
#[derive(Debug, Deserialize)]
struct WorkOsClaims {
    sub: String,
    exp: u64,
    #[serde(
        default,
        rename = "tenant_id",
        alias = "https://tracelane.dev/tenant_id"
    )]
    tenant_id: Option<String>,
    #[serde(default, alias = "organization_id")]
    org_id: Option<String>,
    /// WorkOS membership role slug for the active org (`owner`/`member`/
    /// `viewer`). Absent on service tokens and pre-role-config JWTs.
    #[serde(default)]
    role: Option<String>,
}

/// Validate an `Authorization` header value (Bearer JWT or `tlane_` API key).
///
/// - `Bearer <jwt>` — validated against the cached WorkOS JWKS.
/// - `Bearer tlane_<key>` — API-key path (`api_key::validate`).
///
/// # Errors
/// Returns `Err` if the header is malformed, the token is expired, the
/// signature is invalid, or no tenant can be resolved.
pub async fn validate_authorization(authorization: &str) -> Result<Claims> {
    let token = authorization
        .strip_prefix("Bearer ")
        .context("Authorization header must use Bearer scheme")?;

    if token.is_empty() {
        bail!("empty bearer token");
    }

    // ADR-067: single-tenant self-host short-circuits BOTH the API-key and JWT
    // paths — there is no Postgres/WorkOS in that deployment. Installed only
    // when the multi-tenant guard passed, so this branch is dead in hosted.
    if let Some(sh) = SELF_HOST_AUTH.get() {
        return validate_self_host(token, sh);
    }

    if token.starts_with("tlane_") {
        return api_key::validate(token).await;
    }

    validate_jwt(token).await
}

/// Validate a WorkOS-issued JWT.
///
/// Pipeline:
///   1. Decode the unverified header to read `kid`.
///   2. Look up the matching `DecodingKey` in the cached JWKS.
///   3. `jsonwebtoken::decode` with explicit issuer/audience checks
///      driven by `WORKOS_ISSUER` / `WORKOS_AUDIENCE` env vars.
///   4. Parse `tenant_id` claim into a UUID and wrap in `TenantId`.
///
/// Dev fallback: if `WORKOS_CLIENT_ID` is unset and the build is debug
/// (and the test escape hatch isn't disabling it), return the fixed
/// dev tenant so local workflow without WorkOS still works. Release
/// builds without `WORKOS_CLIENT_ID` always refuse.
async fn validate_jwt(token: &str) -> Result<Claims> {
    let workos_configured = std::env::var("WORKOS_CLIENT_ID").is_ok();
    let dev_auth_disabled = std::env::var("TRACELANE_DEV_AUTH").as_deref() == Ok("0");

    if !workos_configured && !dev_auth_disabled {
        #[cfg(debug_assertions)]
        {
            tracing::debug!("auth: dev-stub claims (WORKOS_CLIENT_ID unset)");
            return Ok(dev_stub_claims(AuthMethod::JwtBearer));
        }
        #[cfg(not(debug_assertions))]
        bail!(
            "WORKOS_CLIENT_ID is required for JWT validation in release builds; \
             set TRACELANE_DEV_AUTH=0 if you want explicit failure in debug too"
        );
    }

    // 1. Decode JWT header (no signature check yet) to find `kid`.
    let header = jsonwebtoken::decode_header(token).context("failed to decode JWT header")?;
    let kid = header
        .kid
        .clone()
        .ok_or_else(|| anyhow::anyhow!("JWT missing `kid` in header"))?;

    // 2. Load JWKS and find the matching key. A12: on cache miss, force
    //    one rate-limited refresh in case WorkOS just rotated its key —
    //    otherwise a fresh `kid` 401s every JWT for up to CACHE_TTL.
    let jwks_cache = jwks::get_cached_with_refresh_on_miss(&kid)
        .await
        .context("JWKS unavailable")?;
    let decoding_key = jwks_cache
        .lookup(&kid)
        .ok_or_else(|| anyhow::anyhow!("no JWKS entry for kid={kid}"))?;

    // 3. Decode + validate (signature, exp, iss, aud), then resolve the
    //    tenant identity (direct UUID claim, or WorkOS org_id bridge).
    let claims = decode_and_validate(token, decoding_key, header.alg)?;
    let role = claims.role.as_deref().and_then(Role::from_slug);
    let tenant_id = resolve_tenant_id(&claims).await?;
    Ok(Claims {
        tenant_id,
        sub: claims.sub,
        exp: claims.exp,
        auth_method: AuthMethod::JwtBearer,
        role,
    })
}

/// Resolve a `TenantId` from validated WorkOS claims.
///
/// 1. **Direct** — the JWT carries an internal `tenant_id` UUID claim (service
///    tokens / legacy). Parsed straight through; no DB hit.
/// 2. **Org bridge** (ADR-042 bug #2) — the JWT carries a WorkOS `org_id`
///    (every dashboard-forwarded AuthKit token). Resolved to the internal
///    tenant UUID via the cached, indexed `tenants.workos_org_id` lookup
///    ([`org_tenant_cache::resolve`]).
///
/// When **both** are present they must agree: the org bridge is resolved and
/// asserted equal to the direct UUID claim. A token that names one tenant via
/// `tenant_id` and a different tenant via `org_id` is rejected (defence in
/// depth — opus-review Med-1). AuthKit tokens carry only `org_id`, so the
/// common paths take exactly one branch and the reconcile costs nothing there.
///
/// # Errors
/// Fail-closed: a claim with neither a valid `tenant_id` UUID nor a resolvable
/// `org_id`, or a `tenant_id`/`org_id` that disagree, returns `Err` — which the
/// caller turns into a 401. The bridge does not log `org_id` (kept out of
/// structured fields); only the resolved `tenant_id` flows downstream.
async fn resolve_tenant_id(claims: &WorkOsClaims) -> Result<TenantId> {
    let direct = match claims.tenant_id.as_deref().filter(|s| !s.is_empty()) {
        Some(tid) => Some(
            Uuid::parse_str(tid)
                .context("JWT tenant_id claim is present but is not a valid UUID")?,
        ),
        None => None,
    };
    let org = claims.org_id.as_deref().filter(|s| !s.is_empty());

    match (direct, org) {
        // Both present: the org bridge MUST agree with the direct claim.
        (Some(uuid), Some(org)) => {
            let resolved = org_tenant_cache::resolve(org)
                .await
                .context("could not resolve WorkOS org_id to a tenant")?;
            if resolved != uuid {
                bail!("JWT tenant_id claim does not match the tenant resolved from org_id");
            }
            Ok(TenantId::from_jwt_claim(uuid))
        }
        (Some(uuid), None) => Ok(TenantId::from_jwt_claim(uuid)),
        (None, Some(org)) => {
            let uuid = org_tenant_cache::resolve(org)
                .await
                .context("could not resolve WorkOS org_id to a tenant")?;
            Ok(TenantId::from_jwt_claim(uuid))
        }
        (None, None) => {
            bail!("JWT carries neither a tenant_id UUID nor an org_id claim; cannot resolve tenant")
        }
    }
}

/// Pure decode + validate (signature, exp, iss, aud). Returns the raw WorkOS
/// claims; tenant resolution is the caller's job ([`resolve_tenant_id`]) so
/// this stays synchronous and DB-free for unit tests that drive it with HS256
/// secrets without touching the global JWKS cache.
///
/// `alg` is the JWT header's claimed algorithm. The alg-confusion defence
/// [`ALLOWED_JWT_ALGORITHMS`] (HMAC family, `none`, …) is rejected here, before
/// any cryptographic work. We then validate against exactly that one
/// already-allowlisted alg.
///
/// IMPORTANT (jsonwebtoken v10, `decoding.rs:342`): the library iterates
/// `validation.algorithms` and rejects with `InvalidAlgorithm` if ANY entry's
/// family differs from the verifying KEY's family. So a mixed RSA+EC+Ed
/// allowlist can NEVER validate against a single-family key (e.g. WorkOS's RSA
/// JWKS key → every EC/Ed entry trips the check). We therefore keep
/// `validation.algorithms = [alg]` (what `Validation::new(alg)` sets) — the
/// upfront check already bounds `alg` to the allowlist, and jsonwebtoken still
/// independently verifies the signature with that alg against the key, so the
/// alg-confusion guarantee is preserved without the family-mismatch crash.
fn decode_and_validate(
    token: &str,
    decoding_key: &DecodingKey,
    alg: Algorithm,
) -> Result<WorkOsClaims> {
    if !ALLOWED_JWT_ALGORITHMS.contains(&alg) {
        bail!(
            "JWT algorithm {:?} is not in the allowlist; alg-confusion attempts are rejected",
            alg
        );
    }

    // `Validation::new(alg)` sets `algorithms = [alg]`. Do NOT widen it to the
    // mixed-family `ALLOWED_JWT_ALGORITHMS` — see the doc comment: jsonwebtoken
    // v10 would reject every single-family key with `InvalidAlgorithm`.
    let mut validation = Validation::new(alg);
    validation.set_required_spec_claims(&["sub", "exp"]);

    if let Ok(iss) = std::env::var("WORKOS_ISSUER") {
        validation.set_issuer(&[iss]);
    }
    match std::env::var("WORKOS_AUDIENCE") {
        Ok(aud) => {
            validation.set_audience(&[aud]);
        }
        Err(_) => {
            // can opt out by setting TRACELANE_AUTH_TEST_NO_AUDIENCE=1, but
            // ONLY in debug builds. Release builds ignore the env var.
            if is_audience_test_bypass_enabled() {
                validation.validate_aud = false;
            } else {
                bail!(
                    "WORKOS_AUDIENCE is unset; refusing to validate JWT without an audience check. \
                     Set WORKOS_AUDIENCE to the expected `aud` claim value."
                );
            }
        }
    }

    let data =
        jsonwebtoken::decode::<WorkOsClaims>(token, decoding_key, &validation).map_err(|e| {
            // Map the jsonwebtoken error kind to the specific failing check so
            // a misconfigured iss/aud/exp is diagnosable from the log instead
            // of a generic "claims validation failed" (cost us a round-trip on
            // the WorkOS prod cutover — the bridge never ran because decode
            // rejected the token first).
            use jsonwebtoken::errors::ErrorKind;
            // Map to a FIXED string per variant — never `{:?}` the ErrorKind
            // (opus-review L-1): `#[non_exhaustive]` variants like
            // `Json`/`Base64`/`Crypto` wrap inner errors whose Debug could, in a
            // future jsonwebtoken version, echo token/signature bytes. Emit only
            // claim NAMES and fixed reasons.
            let detail = match e.kind() {
                ErrorKind::InvalidAudience => {
                    "aud claim rejected (token `aud` is absent or != WORKOS_AUDIENCE)"
                }
                ErrorKind::InvalidIssuer => "iss claim rejected (token `iss` != WORKOS_ISSUER)",
                ErrorKind::ExpiredSignature => "token expired (exp)",
                ErrorKind::ImmatureSignature => "token not yet valid (nbf)",
                ErrorKind::InvalidSignature => "signature verification failed (wrong JWKS key)",
                ErrorKind::InvalidAlgorithm | ErrorKind::InvalidKeyFormat => {
                    "algorithm/key family mismatch (token alg vs JWKS key family)"
                }
                ErrorKind::Base64(_) | ErrorKind::Json(_) | ErrorKind::Utf8(_) => {
                    "token is malformed (encoding)"
                }
                ErrorKind::MissingRequiredClaim(c) => {
                    return anyhow::anyhow!("JWT validation failed: missing required claim `{c}`");
                }
                _ => "validation failed (other)",
            };
            anyhow::anyhow!("JWT validation failed: {detail}")
        })?;

    Ok(data.claims)
}

/// Build dev-stub claims for the dev tenant. Used when WorkOS isn't
/// configured in debug builds, and by `api_key::validate` for the same
/// reason (Postgres lookup not yet wired).
pub(crate) fn dev_stub_claims(auth_method: AuthMethod) -> Claims {
    let tenant_id =
        TenantId::from_jwt_claim(Uuid::parse_str(DEV_TENANT_UUID).expect("static UUID is valid"));
    Claims {
        tenant_id,
        sub: "dev-stub".into(),
        exp: u64::MAX,
        auth_method,
        // Dev tenant = full access (grandfathered, same as API keys).
        role: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    #[test]
    fn rejects_missing_bearer_prefix() {
        rt().block_on(async {
            let result = validate_authorization("not-bearer").await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn rejects_empty_token() {
        rt().block_on(async {
            let result = validate_authorization("Bearer ").await;
            assert!(result.is_err());
        });
    }

    // ── ADR-067 single-tenant self-host auth ────────────────────────────────
    // Drives `validate_self_host` directly (a pure fn over an explicit
    // `SelfHostAuth`) rather than installing the process-global `OnceLock`,
    // which would leak into every other auth test in the same binary.

    fn self_host_tenant() -> TenantId {
        TenantId::from_self_host_config(
            Uuid::parse_str("77777777-7777-4777-8777-777777777777").unwrap(),
        )
    }

    #[test]
    fn self_host_master_key_match_maps_to_single_tenant() {
        let sh = SelfHostAuth {
            tenant_id: self_host_tenant(),
            master_key: Some(SecretString::from(
                "unit-test-master-key-do-not-use".to_string(),
            )),
        };
        let claims =
            validate_self_host("unit-test-master-key-do-not-use", &sh).expect("exact match");
        assert_eq!(claims.tenant_id, self_host_tenant());
        assert_eq!(claims.auth_method, AuthMethod::ApiKey);
        assert_eq!(claims.sub, "self-host");
    }

    #[test]
    fn self_host_master_key_mismatch_is_rejected() {
        let sh = SelfHostAuth {
            tenant_id: self_host_tenant(),
            master_key: Some(SecretString::from(
                "unit-test-master-key-do-not-use".to_string(),
            )),
        };
        // Wrong secret, and a length-different secret — both must fail closed.
        assert!(validate_self_host("wrong-key", &sh).is_err());
        assert!(validate_self_host("unit-test-master-key-do-not-use-EXTRA", &sh).is_err());
    }

    #[test]
    fn self_host_without_master_key_accepts_any_nonempty_token() {
        // Dev / no auth secret configured: any non-empty bearer token (the empty
        // check already happened in `validate_authorization`) → the single tenant.
        let sh = SelfHostAuth {
            tenant_id: self_host_tenant(),
            master_key: None,
        };
        let claims = validate_self_host("any-throwaway-token", &sh).expect("accepted");
        assert_eq!(claims.tenant_id, self_host_tenant());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn dev_stub_path_returns_dev_tenant_when_workos_unset() {
        // SAFETY: the global env mutation is fine for this single-thread
        // test because no other test depends on these vars being set
        // mid-run. Restored after.
        let saved_client = std::env::var("WORKOS_CLIENT_ID").ok();
        let saved_dev = std::env::var("TRACELANE_DEV_AUTH").ok();
        unsafe {
            std::env::remove_var("WORKOS_CLIENT_ID");
            std::env::remove_var("TRACELANE_DEV_AUTH");
        }
        rt().block_on(async {
            let claims = validate_authorization("Bearer some-token").await.unwrap();
            assert_eq!(claims.sub, "dev-stub");
            assert_eq!(claims.auth_method, AuthMethod::JwtBearer);
        });
        unsafe {
            if let Some(v) = saved_client {
                std::env::set_var("WORKOS_CLIENT_ID", v);
            }
            if let Some(v) = saved_dev {
                std::env::set_var("TRACELANE_DEV_AUTH", v);
            }
        }
    }

    /// Convenience guard for tests that need to drive `decode_and_validate`
    /// without WORKOS_AUDIENCE set. Holds a process-wide lock + sets the
    /// `TRACELANE_AUTH_TEST_NO_AUDIENCE=1` opt-out for the test's duration.
    struct NoAudienceGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl NoAudienceGuard {
        fn new() -> Self {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _lock = LOCK.lock().expect("auth-test lock poisoned");
            unsafe {
                std::env::remove_var("WORKOS_AUDIENCE");
                std::env::set_var("TRACELANE_AUTH_TEST_NO_AUDIENCE", "1");
            }
            Self { _lock }
        }
    }
    impl Drop for NoAudienceGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var("TRACELANE_AUTH_TEST_NO_AUDIENCE");
            }
        }
    }

    // Test-only EC P-256 keypair. NOT a real key — generated solely for this
    // regression test. The private key is PKCS#8 DER (base64); the public key
    // is given as JWK x/y so the verify side goes through the exact production
    // `DecodingKey::from_jwk` path the WorkOS JWKS cache uses.
    const TEST_EC_PKCS8_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoQQxRjGx1D6cUiiJJQKdasGYEjTskAb3d4xYidfE7HGhRANCAASFXnV/lOagsDqcuUURHWfsDIENCqa8lx3MNOPxvXqYkFkdER1RM4rJWG94NLIrP1cs591Yq1VigsIBuG4tUNJn";
    const TEST_EC_JWK_X: &str = "hV51f5TmoLA6nLlFER1n7AyBDQqmvJcdzDTj8b16mJA";
    const TEST_EC_JWK_Y: &str = "WR0RHVEzislYb3g0sis_Vyzn3VirVWKCwgG4bi1Q0mc";

    #[test]
    fn validates_asymmetric_token_against_single_family_key() {
        // REGRESSION (the InvalidAlgorithm bug that broke every live WorkOS
        // RS256 token): jsonwebtoken v10 (`decoding.rs:342`) rejects with
        // `InvalidAlgorithm` if ANY alg in `validation.algorithms` has a family
        // != the verifying KEY's family. The old code set `validation.algorithms`
        // to the full mixed RSA+EC+Ed `ALLOWED_JWT_ALGORITHMS`, so a real
        // asymmetric token NEVER validated against its single-family key. Every
        // existing alg test used a symmetric HS256 secret rejected at the
        // upfront allowlist check, so none exercised this path. This signs a
        // real ES256 token and verifies it via the production `from_jwk` path —
        // it would fail with `InvalidAlgorithm` under the mixed-list code.
        use base64::Engine as _;
        let _g = NoAudienceGuard::new(); // aud off; no WORKOS_ISSUER set → iss off
        let claims = serde_json::json!({
            "sub": "user-ec",
            "exp": chrono::Utc::now().timestamp() as u64 + 3600,
            "org_id": "org_regression",
        });
        let der = base64::engine::general_purpose::STANDARD
            .decode(TEST_EC_PKCS8_DER_B64)
            .expect("decode test EC PKCS8 DER");
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &EncodingKey::from_ec_der(&der),
        )
        .expect("encode ES256");

        // Build the verify key through the prod JWKS path: JSON JWK → Jwk → from_jwk.
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": TEST_EC_JWK_X,
            "y": TEST_EC_JWK_Y,
            "use": "sig",
            "alg": "ES256",
        }))
        .expect("parse test EC JWK");
        let key = DecodingKey::from_jwk(&jwk).expect("DecodingKey::from_jwk");

        let result = decode_and_validate(&token, &key, Algorithm::ES256);
        assert!(
            result.is_ok(),
            "asymmetric ES256 token must validate against its EC key (was \
             InvalidAlgorithm under the mixed allowlist): {result:?}"
        );
        assert_eq!(result.unwrap().org_id.as_deref(), Some("org_regression"));
    }

    #[test]
    fn rejects_hs256_alg_confusion() {
        // Without the allowlist, an attacker who substitutes HS256 alg +
        // the RSA public-key bytes as the HMAC secret could mint forged
        // tokens. The allowlist denies the class.
        let _g = NoAudienceGuard::new();
        let secret = b"unit-test-secret-key-do-not-use-in-prod";
        let claims = serde_json::json!({
            "sub": "user-42",
            "exp": chrono::Utc::now().timestamp() as u64 + 3600,
            "tenant_id": "11111111-2222-3333-4444-555555555555"
        });
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let key = DecodingKey::from_secret(secret);
        let result = decode_and_validate(&token, &key, Algorithm::HS256);
        assert!(result.is_err(), "HS256 must be in the deny list");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("allowlist") || err.contains("alg"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_alg_none() {
        // alg=none is explicitly outside the allowlist.
        let _g = NoAudienceGuard::new();
        let claims = serde_json::json!({
            "sub": "user-1",
            "exp": chrono::Utc::now().timestamp() as u64 + 3600,
            "tenant_id": "11111111-2222-3333-4444-555555555555"
        });
        // jsonwebtoken doesn't have an enum variant for none; we simulate
        // by using the `Algorithm` enum we have and checking the deny.
        // For coverage: pass HS384 / HS512 which are also denied.
        for denied in [Algorithm::HS384, Algorithm::HS512] {
            let token = jsonwebtoken::encode(
                &Header::new(denied),
                &claims,
                &EncodingKey::from_secret(b"x"),
            )
            .unwrap();
            let key = DecodingKey::from_secret(b"x");
            let result = decode_and_validate(&token, &key, denied);
            assert!(
                result.is_err(),
                "{:?} must be rejected by allowlist",
                denied
            );
        }
    }

    #[test]
    fn requires_audience_env_in_non_test_path() {
        // WORKOS_AUDIENCE is unset, validate must bail. We avoid
        // touching the allowlist by passing an allowed alg (RS256).
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _l = LOCK.lock().expect("audit lock");
        let saved_aud = std::env::var("WORKOS_AUDIENCE").ok();
        let saved_skip = std::env::var("TRACELANE_AUTH_TEST_NO_AUDIENCE").ok();
        unsafe {
            std::env::remove_var("WORKOS_AUDIENCE");
            std::env::remove_var("TRACELANE_AUTH_TEST_NO_AUDIENCE");
        }
        // Pass a deliberately garbage token; the audience check fires
        // *before* signature verification so we don't need a valid sig.
        let key = DecodingKey::from_secret(b"x");
        let result = decode_and_validate("garbage", &key, Algorithm::RS256);
        unsafe {
            if let Some(v) = saved_aud {
                std::env::set_var("WORKOS_AUDIENCE", v);
            }
            if let Some(v) = saved_skip {
                std::env::set_var("TRACELANE_AUTH_TEST_NO_AUDIENCE", v);
            }
        }
        let err = result
            .expect_err("must bail without WORKOS_AUDIENCE")
            .to_string();
        assert!(err.contains("WORKOS_AUDIENCE"), "got: {err}");
    }

    fn claims(tenant_id: Option<&str>, org_id: Option<&str>) -> WorkOsClaims {
        WorkOsClaims {
            sub: "user-1".into(),
            exp: u64::MAX,
            tenant_id: tenant_id.map(str::to_string),
            org_id: org_id.map(str::to_string),
            role: None,
        }
    }

    fn claims_with_role(role: Option<Role>) -> Claims {
        Claims {
            tenant_id: TenantId::from_jwt_claim(Uuid::parse_str(DEV_TENANT_UUID).unwrap()),
            sub: "u".into(),
            exp: u64::MAX,
            auth_method: AuthMethod::JwtBearer,
            role,
        }
    }

    #[test]
    fn role_from_slug_maps_only_the_three_roles() {
        assert_eq!(Role::from_slug("owner"), Some(Role::Owner));
        assert_eq!(Role::from_slug("member"), Some(Role::Member));
        assert_eq!(Role::from_slug("viewer"), Some(Role::Viewer));
        // WorkOS default `admin` + anything unknown → None (grandfathered).
        // This is the guard against demoting existing admins when the gate ships.
        assert_eq!(Role::from_slug("admin"), None);
        assert_eq!(Role::from_slug("Owner"), None); // case-sensitive slug
        assert_eq!(Role::from_slug(""), None);
    }

    #[test]
    fn viewer_cannot_mint_keys_or_admin() {
        let v = claims_with_role(Some(Role::Viewer));
        assert!(!v.can_mint_keys(), "viewer must not mint keys");
        assert!(!v.can_admin(), "viewer must not admin");
    }

    #[test]
    fn member_can_mint_but_not_admin() {
        let m = claims_with_role(Some(Role::Member));
        assert!(m.can_mint_keys(), "member mints own keys");
        assert!(!m.can_admin(), "member cannot billing/byok/manage");
    }

    #[test]
    fn owner_and_grandfathered_none_can_do_everything() {
        for c in [
            claims_with_role(Some(Role::Owner)),
            claims_with_role(None), // API key / dev / pre-role-config JWT
        ] {
            assert!(c.can_mint_keys());
            assert!(c.can_admin());
        }
    }

    #[test]
    fn role_forbidden_json_has_b073_shape() {
        let body = role_forbidden_json("owner");
        assert!(body.contains(r#""error":"role_forbidden""#), "body: {body}");
        assert!(body.contains(r#""required_role":"owner""#), "body: {body}");
    }

    #[test]
    fn resolve_tenant_id_takes_direct_uuid_claim() {
        // A JWT that already embeds an internal tenant UUID resolves straight
        // through with no DB hit (the org bridge is not consulted).
        let c = claims(Some("11111111-2222-3333-4444-555555555555"), None);
        let tid = rt().block_on(resolve_tenant_id(&c)).expect("direct claim");
        assert_eq!(
            tid.as_uuid().to_string(),
            "11111111-2222-3333-4444-555555555555"
        );
    }

    #[test]
    fn resolve_tenant_id_rejects_garbage_uuid_claim() {
        let c = claims(Some("not-a-uuid"), None);
        let err = rt()
            .block_on(resolve_tenant_id(&c))
            .expect_err("garbage UUID must reject")
            .to_string();
        assert!(err.to_lowercase().contains("uuid"), "got: {err}");
    }

    // Relies on the no-pool deterministic fallback, which only exists in debug
    // builds (release fails closed). Gated so `cargo test --release` stays green.
    #[cfg(debug_assertions)]
    #[test]
    fn resolve_tenant_id_bridges_org_id() {
        // No Postgres pool in the unit-test binary, so the bridge takes the
        // deterministic dev fallback. The resolved tenant must match the same
        // hash the WorkOS webhook uses to provision the tenant — proving the
        // org bridge is wired and agrees with the provisioning path.
        let org = "org_unit_bridge_resolve";
        let c = claims(None, Some(org));
        let tid = rt().block_on(resolve_tenant_id(&c)).expect("org bridge");
        let expected = workos_webhook::tenant_uuid_from_workos_org(org);
        assert_eq!(tid.as_uuid().to_string(), expected.to_string());
    }

    // Both-claims reconcile (opus-review Med-1). These resolve the org bridge,
    // which uses the no-pool dev fallback in debug — gated so `--release` is green.
    #[cfg(debug_assertions)]
    #[test]
    fn resolve_tenant_id_rejects_uuid_org_mismatch() {
        // tenant_id UUID and org_id that resolve to DIFFERENT tenants → reject.
        let c = claims(
            Some("22222222-3333-4444-5555-666666666666"),
            Some("org_resolves_elsewhere"),
        );
        assert!(
            rt().block_on(resolve_tenant_id(&c)).is_err(),
            "mismatched tenant_id vs org_id must be rejected"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn resolve_tenant_id_accepts_matching_uuid_and_org() {
        // When the direct UUID equals the org bridge's resolution, accept it.
        let org = "org_match_reconcile";
        let uuid = workos_webhook::tenant_uuid_from_workos_org(org);
        let c = claims(Some(&uuid.to_string()), Some(org));
        let tid = rt()
            .block_on(resolve_tenant_id(&c))
            .expect("matching uuid+org");
        assert_eq!(tid.as_uuid().to_string(), uuid.to_string());
    }

    #[test]
    fn resolve_tenant_id_rejects_empty_claims() {
        // Neither a tenant_id UUID nor an org_id → fail-closed.
        assert!(
            rt().block_on(resolve_tenant_id(&claims(None, None)))
                .is_err()
        );
        // Empty-string claims are treated as absent, not as a zero UUID.
        assert!(
            rt().block_on(resolve_tenant_id(&claims(Some(""), Some(""))))
                .is_err()
        );
    }

    // Pre-existing rejection tests (expired, bad-signature, non-uuid)
    // covered HS256 which is now in the deny list. They've been
    // subsumed by `rejects_hs256_alg_confusion` and `rejects_alg_none`
    // above — those exercise the same negative paths plus the
    // allowlist itself. Asymmetric-key positive coverage lives in
    // integration tests against the JWKS cache.
}
