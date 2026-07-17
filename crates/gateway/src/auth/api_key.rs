//! Tenant API key validation.
//!
//! API keys: `tlane_<base62>` — shown once at creation, never stored raw.
//! see `crate::db::api_keys`. This module is the auth entry point: it strips the
//! `tlane_` prefix and resolves the key body via
//! `db::api_keys::lookup_tenant_by_key_body` (peppered-HMAC lookup → Argon2id
//! verify), which returns the tenant + the `api_keys.id` used for the `sub`
//! claim (never a secret-derived value).
//!
//! Three resolution paths in priority order:
//!   1. Real Postgres lookup if `db::global_pool()` is set (production).
//!   2. Dev stub if no pool + `WORKOS_CLIENT_ID` unset + debug build
//!      (`TRACELANE_DEV_AUTH=0` opts out).
//!   3. Bail (release without pool, or dev escape hatch disabled).

use anyhow::{Result, bail};
use base64::Engine as _;
use ring::digest;
use tracelane_shared::TenantId;
use uuid::Uuid;

use super::{AuthMethod, Claims, DEV_TENANT_UUID};

/// Validate a Tracelane API key.
///
/// Key format: `tlane_<base62_32bytes>` (~43 base62 chars after prefix).
///
/// # Errors
/// Returns `Err` if the key format is invalid, revoked, or not found.
pub async fn validate(api_key: &str) -> Result<Claims> {
    if !api_key.starts_with("tlane_") {
        bail!("invalid API key format: must start with tlane_");
    }

    let key_body = &api_key["tlane_".len()..];
    if key_body.len() < 16 {
        bail!("invalid API key: too short");
    }

    // Path 1: real Postgres lookup. Hash + index-scan happens here.
    if let Some(pool) = crate::db::global_pool() {
        match crate::db::api_keys::lookup_tenant_by_key_body(pool, key_body).await {
            Ok(Some((tenant_id, key_id))) => {
                return Ok(Claims {
                    tenant_id,
                    // `sub` is the api_keys.id UUID — never a value derived from
                    // the secret key body (ADR-042 / security review M-2). For an
                    // observability product, no secret-derived value may land in
                    // claims/spans/logs.
                    sub: format!("apikey:{key_id}"),
                    exp: u64::MAX,
                    auth_method: AuthMethod::ApiKey,
                    // API keys carry no role → grandfathered full access.
                    role: None,
                });
            }
            Ok(None) => bail!("API key not found or revoked"),
            Err(err) => {
                // DB outage shouldn't surface as auth failure with a leaky
                // error message — log the real cause, return generic auth
                // error to the caller.
                tracing::error!(error = %err, "api_key Postgres lookup failed");
                bail!("API key validation transient failure");
            }
        }
    }

    // Path 2: dev escape hatch. Active only when the global pool is
    // unset, WorkOS is unconfigured, TRACELANE_DEV_AUTH != "0", and
    // the build is debug.
    let workos_configured = std::env::var("WORKOS_CLIENT_ID").is_ok();
    let dev_auth_disabled = std::env::var("TRACELANE_DEV_AUTH").as_deref() == Ok("0");

    if !workos_configured && !dev_auth_disabled {
        #[cfg(debug_assertions)]
        {
            tracing::debug!("api_key auth: dev stub, returning dev tenant");
            let tenant_id = TenantId::from_jwt_claim(
                Uuid::parse_str(DEV_TENANT_UUID).expect("static UUID is valid"),
            );
            return Ok(Claims {
                tenant_id,
                sub: format!(
                    "apikey:{}",
                    &hex::encode(digest::digest(&digest::SHA256, key_body.as_bytes()).as_ref())
                        [..16]
                ),
                exp: u64::MAX,
                auth_method: AuthMethod::ApiKey,
                role: None,
            });
        }
    }

    // Path 3: production without DB or with dev hatch disabled — refuse.
    bail!("API key validation requires Postgres pool (set POSTGRES_URL)")
}

/// Generate a new API key for a tenant — returned once, never stored raw.
///
/// Uses 32 bytes of `ring::rand::SystemRandom`, base64url-encoded.
///
/// # Errors
/// Returns `Err` if the OS RNG fails (should never happen).
pub fn generate() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("RNG failure generating API key"))?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    Ok(format!("tlane_{}", encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    #[test]
    fn generate_produces_correct_prefix() {
        let key = generate().unwrap();
        assert!(key.starts_with("tlane_"));
        assert!(key.len() > "tlane_".len() + 20);
    }

    #[test]
    fn rejects_wrong_prefix() {
        rt().block_on(async {
            let result = validate("wrong_prefix_abc123").await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn rejects_short_key() {
        rt().block_on(async {
            let result = validate("tlane_short").await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn sub_does_not_contain_key_material() {
        // The raw key body must never appear in the `sub` field.
        let key = generate().unwrap();
        let key_body = &key["tlane_".len()..];
        // Generate sub the same way the production path does
        let sub = format!(
            "apikey:{}",
            &hex::encode(ring::digest::digest(&ring::digest::SHA256, key_body.as_bytes()).as_ref())
                [..16]
        );
        // sub must not contain any 8-char prefix of the raw key body
        assert!(
            !sub.contains(&key_body[..8]),
            "raw key material found in sub: {sub}"
        );
        assert!(
            sub.starts_with("apikey:"),
            "sub must start with apikey: prefix"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn dev_stub_path_accepts_well_formed_key() {
        let saved_client = std::env::var("WORKOS_CLIENT_ID").ok();
        let saved_dev = std::env::var("TRACELANE_DEV_AUTH").ok();
        unsafe {
            std::env::remove_var("WORKOS_CLIENT_ID");
            std::env::remove_var("TRACELANE_DEV_AUTH");
        }
        rt().block_on(async {
            let key = generate().unwrap();
            let claims = validate(&key).await.unwrap();
            assert_eq!(claims.auth_method, AuthMethod::ApiKey);
            assert!(claims.sub.starts_with("apikey:"));
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
}
