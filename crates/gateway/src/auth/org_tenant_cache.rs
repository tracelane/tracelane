//! WorkOS `org_id` → internal tenant-UUID resolution cache (the auth bridge).
//!
//! WorkOS-issued AuthKit access tokens carry the WorkOS organization id
//! (`org_...`), not the internal Tracelane tenant UUID. The dashboard forwards
//! these raw tokens to the gateway (e.g. when calling `/v1/byok/provider-keys`),
//! so `auth::validate_jwt` must bridge `org_id` → tenant UUID before it can
//! populate `Claims.tenant_id`. The authoritative mapping lives in Postgres
//! (`tenants.workos_org_id`, UNIQUE-indexed); this module caches it so the auth
//! hot path stays off Postgres on every request (ADR-035, ADR-042 bug #2).
//!
//! ## Semantics
//!
//! - **Cache:** `moka::future::Cache<String, Uuid>`, 30s TTL, **positives
//!   only**. The org→tenant mapping is effectively immutable once a tenant is
//!   created, so there is no `LISTEN/NOTIFY` channel; the 30s TTL bounds the
//!   window in which an archived tenant (filtered out by the resolver's
//!   `archived_at IS NULL`) could still authenticate — the same staleness
//!   ceiling the entitlement cache uses.
//! - **Single-flight:** concurrent misses for the same org coalesce into one
//!   Postgres query via `try_get_with` (errors are never cached).
//! - **Fail-closed:** a Postgres error, or an `org_id` with no active tenant,
//!   resolves to `Err` → `validate_jwt` returns 401. This is a security path;
//!   unlike the entitlement cache we never fail-open to a guessed tenant.
//! - **Dev/no-pool fallback:** with no Postgres pool installed (local
//!   `cargo run` without `POSTGRES_URL`), resolves via the deterministic
//!   [`super::workos_webhook::tenant_uuid_from_workos_org`] hash so dev and
//!   unit tests work without a DB. Any build with a pool always takes the
//!   authoritative lookup.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context as _, Result};
use moka::future::Cache;
use uuid::Uuid;

/// Staleness ceiling for a cached org→tenant mapping. Matches the entitlement
/// cache's 30s TTL; bounds how long an archived tenant can still authenticate.
const TTL: Duration = Duration::from_secs(30);
/// Max distinct orgs held warm. Bounded so a token-spray against many bogus
/// (but validly-signed) orgs can't grow the cache without limit.
const MAX_CAPACITY: u64 = 100_000;

/// Process-wide org→tenant cache. Lazily built on first use; reads the global
/// Postgres pool installed at startup, so no explicit init wiring is needed.
fn cache() -> &'static Cache<String, Uuid> {
    static CACHE: OnceLock<Cache<String, Uuid>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(MAX_CAPACITY)
            .time_to_live(TTL)
            .build()
    })
}

/// Resolve a WorkOS `org_id` to the internal tenant UUID.
///
/// Cached (30s TTL, positives only — errors and unknown orgs are never cached,
/// so a freshly-provisioned tenant authenticates on its next request). On a
/// miss, performs a single indexed Postgres lookup against
/// `tenants.workos_org_id`; concurrent misses for the same org coalesce.
///
/// # Errors
/// Fail-closed: a Postgres error, or an `org_id` with no active tenant, returns
/// `Err`. The caller turns that into a 401.
pub(crate) async fn resolve(org_id: &str) -> Result<Uuid> {
    let key = org_id.to_string();
    // The init future owns its copy of the org id (`async move`) so it carries
    // no borrow from this stack frame — moka shares it across coalesced callers.
    cache()
        .try_get_with(key.clone(), async move { resolve_uncached(&key).await })
        .await
        .map_err(|e: Arc<anyhow::Error>| anyhow::anyhow!("org→tenant resolve failed: {e}"))
}

/// The uncached resolution: authoritative Postgres lookup when a pool exists.
/// With no pool, ONLY a debug build with WorkOS unconfigured takes the
/// deterministic-hash dev fallback; **release builds always fail closed**
/// (a production gateway must always have Postgres — never silently
/// hash-resolve an org to a tenant).
async fn resolve_uncached(org_id: &str) -> Result<Uuid> {
    match crate::db::global_pool() {
        Some(pool) => crate::db::tenants::get_tenant_id_by_workos_org(pool, org_id)
            .await
            .context("workos_org_id lookup failed")?
            .ok_or_else(|| anyhow::anyhow!("no active tenant for the presented organization")),
        None => {
            let workos_configured = std::env::var("WORKOS_CLIENT_ID").is_ok();
            no_pool_fallback(org_id, workos_configured)
        }
    }
}

/// Dev / no-pool fallback: deterministic hash so local `cargo run` + unit
/// tests resolve an org without a database.
///
/// `tenants` table (prod ids are random), so it must never answer for a
/// real WorkOS-issued token. If WorkOS IS configured (`workos_configured`,
/// i.e. real JWTs are being validated) the fallback refuses even in a debug
/// build — it only serves the pure dev-stub mode (no Postgres, no WorkOS).
#[cfg(debug_assertions)]
fn no_pool_fallback(org_id: &str, workos_configured: bool) -> Result<Uuid> {
    if workos_configured {
        anyhow::bail!(
            "org→tenant bridge: WorkOS is configured but no Postgres pool is installed — \
             refusing the dev hash fallback for a real org token"
        );
    }
    Ok(super::workos_webhook::tenant_uuid_from_workos_org(org_id))
}

/// Release builds fail closed when no pool is configured — the org→tenant
/// bridge is a security path and must resolve against the authoritative
/// `tenants.workos_org_id`, never a guessable hash.
#[cfg(not(debug_assertions))]
fn no_pool_fallback(_org_id: &str, _workos_configured: bool) -> Result<Uuid> {
    anyhow::bail!("org→tenant bridge requires a Postgres pool; refusing to hash-resolve in release")
}

// Tests exercise the no-pool dev fallback, which only exists in debug builds
// (release fails closed). `cargo test` is debug by default; gating keeps
// `cargo test --release` green too.
#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().expect("tokio runtime")
    }

    #[test]
    fn dev_fallback_matches_deterministic_hash() {
        // No global pool is installed in the unit-test binary, so resolve()
        // takes the deterministic dev fallback and must agree with the same
        // hash the WorkOS webhook uses to provision the tenant.
        let org = "org_unit_dev_fallback_match";
        let resolved = rt().block_on(resolve(org)).expect("dev fallback resolves");
        let expected = crate::auth::workos_webhook::tenant_uuid_from_workos_org(org);
        assert_eq!(resolved, expected);
    }

    #[test]
    fn cached_second_call_is_stable() {
        // Two resolves of the same org return the same UUID (cache hit on the
        // second). Distinct org id keeps this test independent of others.
        let org = "org_unit_cache_stable";
        let first = rt().block_on(resolve(org)).expect("first resolve");
        let second = rt().block_on(resolve(org)).expect("second resolve");
        assert_eq!(first, second);
    }

    #[test]
    fn dev_fallback_refuses_when_workos_is_configured() {
        // fallback must refuse even in a debug build — pure fn, no env twiddle.
        let err = no_pool_fallback("org_real_token", true)
            .expect_err("must refuse hash fallback when WorkOS is configured");
        assert!(err.to_string().contains("refusing"), "got: {err}");
        // Pure dev-stub mode (no WorkOS) still resolves.
        assert!(no_pool_fallback("org_pure_dev", false).is_ok());
    }
}
