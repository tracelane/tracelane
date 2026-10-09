//! Tenant API key validation.
//!
//! API keys: `tlane_<base62>` — shown once at creation, never stored raw.
//! Storage + lookup are the peppered-HMAC + Argon2id scheme (ADR-042)
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
use ring::digest;
use tracelane_shared::TenantId;
use uuid::Uuid;

use super::{AuthMethod, Claims, DEV_TENANT_UUID};

/// Validate a Tracelane API key.
///
/// Key format: `tlane_<base62_32bytes>` (~43 base62 chars after prefix).
///
/// Returns the claims and the branch that answered (B-568 I1) — the branch is
/// timing metadata only and never widens or narrows the grant.
///
/// # Errors
/// Returns `Err` if the key format is invalid, revoked, or not found.
pub async fn validate(api_key: &str) -> Result<(Claims, super::AuthPath)> {
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
            Ok(Some(auth)) => {
                let crate::db::api_keys::KeyAuth {
                    tenant_id,
                    key_id,
                    scope: key_scope,
                    budget_usd_monthly,
                    rate_limit_rpm,
                    budget_reset,
                    governance,
                    path,
                } = auth;
                // OG-20: the authentication-time half of the key's policy — an
                // unparseable stored policy, then `source_ips` against the address B-594
                // derived for this request (`preauth_limiter::client_ip`, ONE derivation).
                // Here, not in admission, so EVERY route the key can reach is covered:
                // reads, ingest and companions as well as dispatch. Fail-CLOSED.
                enforce_source(governance.as_deref())?;
                // rev5 M6: the WORKSPACE policy's `source_ips` bind every key too — one
                // warm entitlement-cache read, the same address, the same refusal.
                if let Some(d) = workspace_source_refusal(
                    crate::entitlement_cache::global(),
                    &tenant_id,
                    crate::db::api_keys::current_client_ip(),
                )
                .await
                {
                    return Err(super::PolicyRefused(d).into());
                }
                let claims = Claims {
                    tenant_id,
                    // `sub` is the api_keys.id UUID — never a value derived from
                    // the secret key body (ADR-042 / security review M-2). For an
                    // observability product, no secret-derived value may land in
                    // claims/spans/logs.
                    sub: format!("apikey:{key_id}"),
                    auth_method: AuthMethod::ApiKey,
                    // API keys carry no role. That is NOT full access: since PL-9b
                    // `has_no_role_system` covers only the self-host master key, so a
                    // tenant key is denied `can_admin`. Per-capability predicates decide
                    // what it may do (e.g. `can_write_prompts` admits it, A8).
                    role: None,
                    // A13: the capability resolved at auth time. A key minted
                    // before A13 has scope IS NULL -> LegacyFullSurface, so it
                    // keeps working exactly as it did; a scoped key carries only
                    // what it was granted.
                    key_scope,
                    // GWY-43: carried on the claims so the hot path enforces a
                    // budget and a per-key rate limit without a second lookup.
                    budget_usd_monthly,
                    rate_limit_rpm,
                    // BILL-01 A3: same SELECT, same zero-extra-round-trip shape.
                    budget_reset,
                    // OG-20 / OG-23: same SELECT again.
                    governance,
                };
                return Ok((claims, super::AuthPath::ApiKey(path)));
            }
            Ok(None) => bail!("API key not found or revoked"),
            // B-594: refused BEFORE the store by the source's failed-lookup
            // budget. Passed through typed — it is neither an outage (503) nor a
            // wrong key (401), and `auth::failure` answers it 429.
            Err(err) if err.is::<crate::db::api_keys::AuthThrottled>() => return Err(err),
            Err(err) => {
                // B-391 (c): a DB outage is NOT an auth failure. Typed, so every
                // handler answers 503 `auth_unavailable` (via `auth::failure`)
                // instead of 401 — a customer must not rotate a good key because
                // Neon was resuming. The real cause is logged here and carried
                // in the error for the log line at the handler; the client sees
                // only the static message.
                return Err(super::AuthStoreUnavailable::new(format!(
                    "api_key Postgres lookup failed: {err:#}"
                ))
                .into());
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
            let claims = Claims {
                tenant_id,
                sub: format!(
                    "apikey:{}",
                    &hex::encode(digest::digest(&digest::SHA256, key_body.as_bytes()).as_ref())
                        [..16]
                ),
                auth_method: AuthMethod::ApiKey,
                role: None,
                key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
                // GWY-43: no budget and no per-key rate override on this credential.
                budget_usd_monthly: None,
                rate_limit_rpm: None,
                budget_reset: crate::spend::BudgetReset::Monthly,
                governance: None,
            };
            return Ok((claims, super::AuthPath::Static));
        }
    }

    // Path 3: production without DB or with dev hatch disabled — refuse.
    bail!("API key validation requires Postgres pool (set POSTGRES_URL)")
}

/// rev5 `M6`: the WORKSPACE policy's `source_ips` against `ip`, for an API key of `tenant`
/// — `Some(policy_ip_denied)` when they refuse it. `None` with no control plane (no cache:
/// nothing can have been set) or no workspace policy. Fail-CLOSED: no derivable address
/// under a CIDR rule is a refusal. A WorkOS session is not bound (the dashboard's admin
/// plane has its own allowlist, `OG-36`).
pub(crate) async fn workspace_source_refusal(
    cache: Option<&std::sync::Arc<crate::entitlement_cache::EntitlementCache>>,
    tenant: &tracelane_shared::TenantId,
    ip: Option<std::net::IpAddr>,
) -> Option<tracelane_shared::key_policy::Denial> {
    let cache = cache?;
    let e = cache.resolved(*tenant.as_uuid()).await;
    // rev6 N4: a stored workspace policy that does not parse cannot be shown to carry no
    // `source_ips` rule — refuse, as every other OG-20 reader of an invalid policy does
    // (admission refuses inference `policy_invalid` for the same document). Fail-CLOSED.
    if matches!(
        e.controls.policy,
        Some(tracelane_shared::key_policy::LayerPolicy::Invalid)
    ) {
        return Some(tracelane_shared::key_policy::Denial::new(
            403,
            "policy_invalid",
            "policy",
            tracelane_shared::key_policy::Origin::Workspace,
            None,
            "this workspace's policy could not be read, so API keys are refused — an owner must \
             correct or clear it (PUT /v1/controls/policy)"
                .to_owned(),
        ));
    }
    let p = e.controls.policy()?;
    p.check_source(tracelane_shared::key_policy::Origin::Workspace, ip)
        .err()
}

/// `OG-20`: the authentication-time half of a key's policy — an unparseable stored
/// policy, then `source_ips` against the address the pre-auth layer derived for THIS
/// request (`preauth_limiter::client_ip`, carried on the request's cold-gate scope).
///
/// # Errors
/// [`super::PolicyRefused`] (403 `policy_invalid` / `policy_ip_denied`). Fail-CLOSED: no
/// derivable address under a CIDR rule is a refusal.
pub(crate) fn enforce_source(
    governance: Option<&tracelane_shared::key_policy::Governance>,
) -> std::result::Result<(), super::PolicyRefused> {
    match governance {
        Some(g) => g
            .check_source(crate::db::api_keys::current_client_ip())
            .map_err(super::PolicyRefused),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OG-20: the CIDR rule is judged on the address B-594's derivation produced — read
    /// back from the request scope — and a spoofed forwarding header from a PUBLIC peer
    /// does not move it. Fail-CLOSED with no scope at all.
    #[tokio::test]
    async fn og20_source_ips_judge_the_derived_address_not_a_spoofed_header() {
        use axum::http::{HeaderMap, HeaderValue};
        use std::sync::atomic::AtomicU64;
        let gov = tracelane_shared::key_policy::Governance::from_columns(
            None,
            None,
            None,
            Some(&serde_json::json!({ "source_ips": ["10.0.0.0/8"] })),
        )
        .unwrap();
        let in_scope = |ip: Option<std::net::IpAddr>| crate::db::api_keys::ColdGateScope {
            gate: crate::preauth_limiter::PreAuthLimiter::new(1).gate_for_tests(),
            source: 0,
            client_ip: ip,
            throttled_retry_after: AtomicU64::new(0),
        };
        // A PUBLIC peer forging both forwarding headers with an allowed address: the
        // derivation ignores them, the peer is the source, and the key is refused.
        let mut forged = HeaderMap::new();
        forged.insert("cf-connecting-ip", HeaderValue::from_static("10.1.1.1"));
        forged.insert("x-forwarded-for", HeaderValue::from_static("10.1.1.1"));
        let derived = crate::preauth_limiter::client_ip(
            &forged,
            Some("203.0.113.9".parse().unwrap()),
            crate::providers::translation_policy::auth_throttle_policy(),
        );
        assert_eq!(derived, Some("203.0.113.9".parse().unwrap()));
        let err = crate::db::api_keys::with_cold_gate(in_scope(derived), async {
            enforce_source(Some(&gov))
        })
        .await
        .unwrap_err();
        assert_eq!(err.0.code, "policy_ip_denied");
        // Behind a PRIVATE hop the believed header decides — inside the CIDR → allowed.
        let derived = crate::preauth_limiter::client_ip(
            &forged,
            Some("172.18.0.5".parse().unwrap()),
            crate::providers::translation_policy::auth_throttle_policy(),
        );
        assert_eq!(derived, Some("10.1.1.1".parse().unwrap()));
        assert!(
            crate::db::api_keys::with_cold_gate(in_scope(derived), async {
                enforce_source(Some(&gov))
            })
            .await
            .is_ok()
        );
        // No request scope (no address) → refused, never allowed.
        assert_eq!(
            enforce_source(Some(&gov)).unwrap_err().0.code,
            "policy_ip_denied"
        );
        // As an auth failure it is a 403 with its own code, never the 401 a wrong key gets.
        let e: anyhow::Error = enforce_source(Some(&gov)).unwrap_err().into();
        assert_eq!(
            crate::auth::failure_status(&e),
            axum::http::StatusCode::FORBIDDEN
        );
        assert_eq!(crate::auth::failure_code(&e), "policy_ip_denied");
        // No governance: unchanged.
        assert!(enforce_source(None).is_ok());
    }

    /// A well-formed `tlane_` key for the tests below. The production
    /// generator lives in `db::api_keys` (peppered, minted into Postgres); the
    /// old `generate()` here fed nothing but these tests and was deleted (B-390).
    fn generate() -> Result<String> {
        use base64::Engine as _;
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        Ok(format!(
            "tlane_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
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
            let (claims, path) = validate(&key).await.unwrap();
            assert_eq!(claims.auth_method, AuthMethod::ApiKey);
            // B-568 I1: the dev stub touches no store, so it is neither warm nor cold.
            assert_eq!(path, crate::auth::AuthPath::Static);
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
