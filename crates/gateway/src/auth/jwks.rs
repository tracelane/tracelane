//! WorkOS JWKS fetching, parsing, and caching.
//!
//! Hot path: `kid` -> `&DecodingKey` HashMap lookup. The JWKS endpoint is
//! fetched lazily on first request and cached for `CACHE_TTL` (5 minutes).
//! Cache writes are wait-free via `ArcSwap`.
//!
//! WorkOS JWKS URL: `https://api.workos.com/sso/jwks/{client_id}`
//! Override with `WORKOS_JWKS_URL`. Tests inject keys via
//! `set_cache_for_testing`.

use anyhow::{Context as _, Result, anyhow};
use arc_swap::ArcSwap;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(300);

/// Minimum interval between on-miss refresh attempts (A12). Defends against
/// a malicious or bug-induced storm of unknown-`kid` JWTs forcing a fetch
/// loop against WorkOS; legitimate key rotation only needs one fetch to
/// converge.
const ON_MISS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

/// Parsed JWKS — `kid` -> `DecodingKey`, fetched at `fetched_at`.
pub struct JwksCache {
    pub keys: HashMap<String, DecodingKey>,
    pub fetched_at: Instant,
}

impl JwksCache {
    pub fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < CACHE_TTL
    }

    /// Lookup a decoding key by `kid` (JWT header `kid` claim).
    pub fn lookup(&self, kid: &str) -> Option<&DecodingKey> {
        self.keys.get(kid)
    }

    /// Build a `JwksCache` from a parsed `JwkSet`. Each JWK must carry a
    /// `kid`; otherwise the entry is rejected (we cannot route a JWT to a
    /// key without one).
    pub fn from_jwk_set(set: &JwkSet) -> Result<Self> {
        let mut keys = HashMap::with_capacity(set.keys.len());
        for jwk in &set.keys {
            let kid = jwk
                .common
                .key_id
                .clone()
                .ok_or_else(|| anyhow!("JWK missing required `kid` claim"))?;
            let key = DecodingKey::from_jwk(jwk)
                .with_context(|| format!("failed to build DecodingKey for kid={kid}"))?;
            keys.insert(kid, key);
        }
        Ok(Self {
            keys,
            fetched_at: Instant::now(),
        })
    }
}

static CACHE: std::sync::OnceLock<Arc<ArcSwap<Option<Arc<JwksCache>>>>> =
    std::sync::OnceLock::new();

fn cache() -> &'static Arc<ArcSwap<Option<Arc<JwksCache>>>> {
    CACHE.get_or_init(|| Arc::new(ArcSwap::from_pointee(None)))
}

/// Inject a `JwksCache` into the global cache. Test-only seam — the
/// `validate_jwt` path then sees these keys instead of fetching from
/// WorkOS. Used by the integration tests in `auth::mod::tests`.
#[doc(hidden)]
pub fn set_cache_for_testing(value: Arc<JwksCache>) {
    cache().store(Arc::new(Some(value)));
}

/// Clear the JWKS cache. Test-only.
#[doc(hidden)]
pub fn clear_cache_for_testing() {
    cache().store(Arc::new(None));
}

/// Singleflight lock for the stale-refresh path (mythos round-2 B4).
/// At TTL expiry under high RPS, N concurrent requests would each
/// trigger their own JWKS fetch — DoS'ing WorkOS and ourselves. The
/// tokio `Mutex` lets exactly one task fetch; others re-read the
/// (just-refreshed) ArcSwap after the holder releases.
static REFRESH_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn refresh_lock() -> &'static tokio::sync::Mutex<()> {
    REFRESH_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Fetch the WorkOS JWKS, using the in-memory cache if still fresh.
///
/// # Errors
/// Returns `Err` if `WORKOS_CLIENT_ID` is not set, the HTTP request fails,
/// the body is not valid JSON, or any JWK lacks a `kid` claim.
pub async fn get_cached() -> Result<Arc<JwksCache>> {
    let current = cache().load();
    if let Some(ref cached) = **current {
        if cached.is_fresh() {
            return Ok(Arc::clone(cached));
        }
    }

    // B4: singleflight — only one task does the refresh per stale window.
    let _guard = refresh_lock().lock().await;
    // Re-check: another task may have refreshed while we were waiting.
    let current = cache().load();
    if let Some(ref cached) = **current {
        if cached.is_fresh() {
            return Ok(Arc::clone(cached));
        }
    }

    let fresh = fetch_from_workos().await?;
    let arc = Arc::new(fresh);
    cache().store(Arc::new(Some(Arc::clone(&arc))));
    Ok(arc)
}

/// Track the last on-miss refresh attempt so a flood of unknown-`kid` JWTs
/// can't storm WorkOS. Mutex is fine — only the rare cache-miss path locks
/// it, never the fresh-cache hot path.
static LAST_ON_MISS_REFRESH: std::sync::OnceLock<Mutex<Option<Instant>>> =
    std::sync::OnceLock::new();

fn last_on_miss_refresh() -> &'static Mutex<Option<Instant>> {
    LAST_ON_MISS_REFRESH.get_or_init(|| Mutex::new(None))
}

/// Look up a `kid` in the cached JWKS; on miss, force one refresh
/// (rate-limited to `ON_MISS_REFRESH_COOLDOWN`) before reporting failure.
///
/// A12 fix: previously a freshly-rotated WorkOS signing key would 401
/// every JWT for up to 5 minutes (until the TTL expired). The on-miss
/// refresh closes that window to one round-trip + at-most-one cooldown
/// gap.
///
/// Returns `Ok(Arc<JwksCache>)` with the (possibly refreshed) cache.
/// Callers still do their own `lookup(kid)` against the result.
pub async fn get_cached_with_refresh_on_miss(kid: &str) -> Result<Arc<JwksCache>> {
    let cache = get_cached().await?;
    if cache.lookup(kid).is_some() {
        return Ok(cache);
    }

    // Cache miss. Refresh if we haven't tried within the cooldown.
    // parking_lot::Mutex doesn't poison — consistent with audit.rs.
    {
        let mut guard = last_on_miss_refresh().lock();
        if let Some(last) = *guard {
            if last.elapsed() < ON_MISS_REFRESH_COOLDOWN {
                // Cooled-down — just return the cache. The caller's
                // lookup will fail and surface a 401 to the client.
                // Better one 401 than DoS-storming WorkOS.
                return Ok(cache);
            }
        }
        *guard = Some(Instant::now());
    }

    tracing::info!(
        kid = %kid,
        "JWT carried unknown kid — refreshing JWKS (A12 on-miss refresh)"
    );
    match fetch_from_workos().await {
        Ok(fresh) => {
            let arc = Arc::new(fresh);
            self::cache().store(Arc::new(Some(Arc::clone(&arc))));
            Ok(arc)
        }
        Err(e) => {
            // Refresh failed — log and fall back to the stale cache.
            // The caller's lookup against the stale cache will fail and
            // a 401 will be returned, which is the safe outcome.
            tracing::warn!(error = %e, "JWKS on-miss refresh failed; keeping stale cache");
            Ok(cache)
        }
    }
}

/// Hosts permitted as a `WORKOS_JWKS_URL` override target.
///
/// blindly via bare `reqwest::get`. An operator who controls DNS
/// (or who fat-fingers the env var into an attacker-controlled
/// host) could substitute a JWKS that contains the attacker's
/// public key — every subsequent JWT signed by that key would
/// validate, bypassing WorkOS entirely.
///
/// The allowlist permits the bare apex (`workos.com` exact match) and
/// any subdomain (`<sub>.workos.com` suffix match). The leading dot
/// in the suffix entry is load-bearing — a bare `"workos.com"` would
/// suffix-match `"not-workos.com"` (confusable smuggle), which is
/// the exact attack this allowlist exists to prevent.
const ALLOWED_JWKS_HOST_SUFFIXES: &[&str] = &[".workos.com"];
const ALLOWED_JWKS_HOST_EXACT: &[&str] = &["workos.com"];

/// Validate `url` host against the JWKS allowlist + SSRF guard.
///
/// Returns `Err` with a generic "not permitted" message on any
/// rejection — the specific reason is logged but never surfaced
/// to the caller (the caller is a JWT validation path; leaking
/// internal hostnames here is a small information-disclosure
/// vector).
async fn validate_jwks_url(url: &str) -> Result<()> {
    // Step 1: host-suffix allowlist (cheap; no network). Done BEFORE
    // the SSRF guard so unallowed hosts never even DNS-resolve.
    let parsed = reqwest::Url::parse(url).context("WORKOS_JWKS_URL not parseable")?;
    match parsed.scheme() {
        "https" | "http" => {}
        _ => anyhow::bail!("JWKS URL not permitted"),
    }
    if !is_jwks_test_bypass_enabled() {
        let Some(host) = parsed.host_str() else {
            anyhow::bail!("JWKS URL not permitted");
        };
        let permitted = ALLOWED_JWKS_HOST_EXACT.contains(&host)
            || ALLOWED_JWKS_HOST_SUFFIXES
                .iter()
                .any(|suffix| host.ends_with(suffix));
        if !permitted {
            tracing::warn!(host, "WORKOS_JWKS_URL host not in allowlist");
            anyhow::bail!("JWKS URL not permitted");
        }
    }

    // Step 2: SSRF guard (does DNS — could fail in air-gapped envs;
    // production deployments MUST keep this path SSRF-clean).
    crate::ssrf_guard::validate_url(url).await.map_err(|e| {
        tracing::warn!(error = %e, "WORKOS_JWKS_URL rejected by SSRF guard");
        anyhow!("JWKS URL not permitted")
    })?;

    Ok(())
}

/// Test-only override for the JWKS host allowlist.
/// Release builds always return `false` regardless of env state
/// (same pattern as `TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS`).
#[cfg(debug_assertions)]
fn is_jwks_test_bypass_enabled() -> bool {
    std::env::var("TRACELANE_JWKS_TEST_ALLOW_ANY_HOST").as_deref() == Ok("1")
}

#[cfg(not(debug_assertions))]
fn is_jwks_test_bypass_enabled() -> bool {
    false
}

async fn fetch_from_workos() -> Result<JwksCache> {
    let client_id = std::env::var("WORKOS_CLIENT_ID")
        .context("WORKOS_CLIENT_ID env var required for JWT validation")?;

    let base_url = std::env::var("WORKOS_JWKS_URL")
        .unwrap_or_else(|_| format!("https://api.workos.com/sso/jwks/{}", client_id));

    // BEFORE the HTTP call, so a misconfigured / DNS-poisoned host
    // cannot inject signing keys.
    validate_jwks_url(&base_url).await?;

    // Use the same hardened reqwest client as the provider hot path.
    // 5-second timeout: JWKS fetch is on the auth critical path; a
    // hanging upstream would block every JWT validation.
    let client = crate::ssrf_guard::safe_client_builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("build JWKS reqwest client")?;
    let response = client
        .get(&base_url)
        .send()
        .await
        .context("failed to fetch WorkOS JWKS")?;

    let status = response.status();
    if !status.is_success() {
        // R2 C-3 symmetric: do NOT propagate the response body.
        // WorkOS error bodies have included internal request IDs
        // and (historically) the requesting client_id.
        let _body = response.text().await.unwrap_or_default();
        tracing::warn!(%status, "WorkOS JWKS fetch returned non-2xx");
        anyhow::bail!("WorkOS JWKS fetch failed: status {status}");
    }

    let raw = response
        .text()
        .await
        .context("failed to read JWKS response")?;
    let set: JwkSet = serde_json::from_str(&raw).context("failed to parse JWKS JSON")?;
    JwksCache::from_jwk_set(&set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_jwk_set_rejects_kid_less_jwk() {
        // A JWK without `kid` cannot be routed to from a JWT header, so we
        // reject the entire set rather than silently dropping the entry.
        // Use match (not unwrap_err) — JwksCache holds DecodingKey which
        // doesn't impl Debug, and unwrap_err requires Debug on the Ok type.
        let raw = serde_json::json!({
            "keys": [{
                "kty": "oct",
                "k": "c2VjcmV0",
                "alg": "HS256"
            }]
        });
        let set: JwkSet = serde_json::from_value(raw).unwrap();
        match JwksCache::from_jwk_set(&set) {
            Ok(_) => panic!("kid-less JWK must be rejected"),
            Err(e) => assert!(e.to_string().contains("kid"), "msg: {e}"),
        }
    }

    #[test]
    fn fresh_cache_is_fresh() {
        let cache = JwksCache {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
        };
        assert!(cache.is_fresh());
    }

    #[test]
    fn lookup_returns_none_for_unknown_kid() {
        let cache = JwksCache {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
        };
        assert!(cache.lookup("nope").is_none());
    }


    /// Hold a process-wide lock + reset the JWKS test bypass for
    /// every allowlist test so concurrent tests don't see each
    /// other's env mutations.
    struct JwksEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl JwksEnvGuard {
        fn new() -> Self {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _lock = LOCK.lock().expect("jwks env lock poisoned");
            unsafe {
                std::env::remove_var("TRACELANE_JWKS_TEST_ALLOW_ANY_HOST");
            }
            Self { _lock }
        }
    }

    /// Pure host-suffix check (no DNS) so tests run in air-gapped
    /// sandboxes. The allowlist + SSRF wiring is exercised by
    /// `validate_jwks_url` directly.
    fn host_allowed(host: &str) -> bool {
        ALLOWED_JWKS_HOST_EXACT.contains(&host)
            || ALLOWED_JWKS_HOST_SUFFIXES
                .iter()
                .any(|suffix| host.ends_with(suffix))
    }

    #[test]
    fn host_allowlist_accepts_workos_canonical() {
        assert!(host_allowed("api.workos.com"));
    }

    #[test]
    fn host_allowlist_accepts_workos_regional_subdomain() {
        assert!(host_allowed("api-eu.workos.com"));
        assert!(host_allowed("api-us.workos.com"));
    }

    #[test]
    fn host_allowlist_accepts_bare_workos() {
        assert!(host_allowed("workos.com"));
    }

    #[test]
    fn host_allowlist_rejects_unrelated_host() {
        assert!(!host_allowed("evil.example.com"));
    }

    #[test]
    fn host_allowlist_rejects_workos_lookalike_suffix_smuggle() {
        // Confusable: workos.com.evil.com — suffix match would
        // incorrectly accept this if we forgot the leading dot.
        assert!(!host_allowed("workos.com.evil.com"));
        assert!(!host_allowed("not-workos.com"));
    }

    #[tokio::test]
    async fn validate_jwks_url_rejects_attacker_host_before_dns() {
        let _g = JwksEnvGuard::new();
        // Reaches the allowlist check BEFORE any DNS resolution,
        // so this test passes even in air-gapped sandboxes.
        let result = validate_jwks_url("https://evil.example.com/jwks").await;
        let err = result.expect_err("evil host must be rejected");
        assert!(
            err.to_string().contains("not permitted"),
            "expected allowlist rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn validate_jwks_url_rejects_non_http_scheme() {
        let _g = JwksEnvGuard::new();
        let result = validate_jwks_url("ftp://api.workos.com/jwks").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_jwks_url_rejects_imds_via_ssrf_guard() {
        let _g = JwksEnvGuard::new();
        // 169.254.169.254 is an IP literal so the allowlist host
        // check rejects it before SSRF gets a chance — but either
        // way it's rejected. The SSRF guard is the second layer.
        let result = validate_jwks_url("http://169.254.169.254/jwks").await;
        assert!(result.is_err(), "IMDS URL must be rejected");
    }

    #[tokio::test]
    async fn validate_jwks_url_rejects_lookalike_via_allowlist() {
        let _g = JwksEnvGuard::new();
        // Confusable: workos.com.evil.com — must not match.
        let result = validate_jwks_url("https://workos.com.evil.com/jwks").await;
        let err = result.expect_err("lookalike host must be rejected");
        assert!(err.to_string().contains("not permitted"));
    }
}
