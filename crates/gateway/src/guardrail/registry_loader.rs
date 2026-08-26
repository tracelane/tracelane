//! Per-workspace capability-registry loader (the guardrail spec §2.3).
//! Resolves a tenant's registered tool capabilities (the `tool_capabilities`
//! Postgres table, Migration 13) into an in-process [`CapabilityRegistry`],
//! Moka-cached so warm reads never touch Postgres — mirrors the
//! `entitlement_cache` pattern (ADR-035).
//!
//! Safe-default (founder rule): a tenant with no registered tools resolves to an
//! empty → **permissive** registry (untagged tools hold no caps, not blocked).
//! ≥ 1 row → **enforcing**.
//!
//! Store-outage posture: a resolver error must NEVER silently drop an
//! *enforcing* tenant to permissive (that would disable R3 definition-pinning +
//! R4 lethal-trifecta enforcement on a DB blip). On error we reuse the tenant's
//! **last-known** registry (survives the moka TTL, mirrors `entitlement_cache`,
//! ADR-035) so a configured tenant keeps its real posture. With **no** last-known
//! (cold cache + store down) we fall back to **PERMISSIVE** (available), not
//! enforcing: a tenant only becomes enforcing by registering tools, and such a
//! tenant — once loaded — is covered by `last_known`. Failing a cold/unconfigured
//! tenant CLOSED would turn a Postgres blip into customer-facing 403s on agentic
//! traffic for any R4-entitled (paid) tenant — under ENFORCING every untagged
//! tool resolves to all-caps, so R4 blocks a converged trifecta. The load-bearing
//!  fix is the last-known preservation (a warm enforcing tenant never drops
//! to permissive); the cold edge stays available. (This was briefly cold→enforcing
//! on 2026-07-28; reverted the same day after confirming R4 halts (403) and is
//! plan-default-on for paid tiers — a DB blip must not become a launch-night
//! outage. Empirical fail-closed validation for configured tenants is tracked as
//! the chaos test.)

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use moka::future::Cache;
use uuid::Uuid;

use crate::guardrail::capability::{CapabilityRegistry, CapabilitySet};

/// Tenants held in the registry cache.
///
/// Raised from 10,000, which was EXACTLY the three-month user target — a ceiling
/// sitting on the number you plan to reach is a ceiling you will hit, and it
/// would present as this same bug: entries evicted before reuse, every request
/// paying a blocking resolve.
const MAX_CAPACITY: u64 = 50_000;
/// Cache lifetime for a tenant's capability registry.
///
/// **900s, raised from 30s (B-256).** At 30 seconds this cache could not hit:
/// production requests arrive roughly every 400 seconds, so every request found
/// an expired entry and paid a blocking Postgres resolve. Measured on prod
/// 2026-08-18, that resolve was **14.1ms of a 202.3ms request** — the third
/// largest stage, behind only the auth cache (which had the same defect at 60s)
/// and the BYOK key cache (300s, same defect).
///
/// This module's own doc says it "mirrors `entitlement_cache`". It mirrored the
/// BROKEN version: `entitlement_cache` was *itself* 30s once, for exactly this
/// reason, and its comment records the fix — "a blocking Postgres re-resolve on
/// EVERY request from a low-QPS tenant ... ~72ms p50 gateway overhead ... while
/// the warm/sustained path measured ~1.6ms". It moved to 900s. This did not.
///
/// **A longer TTL is not a freshness trade here, because eviction is explicit.**
/// Every tool-pin write path calls `GuardrailEngine::invalidate_registry`
/// (`tool_pins_api.rs`, three call sites), so a customer's change takes effect on
/// the NEXT request regardless of this value. The TTL is the backstop for changes
/// that arrive without passing through those routes.
///
/// **Its honest limit:** that invalidation is process-local. With one gateway
/// instance it is complete. Run two, and this TTL becomes the cross-instance
/// staleness bound — at which point the invalidation needs to become a broadcast,
/// not a longer or shorter number here.
const TTL: Duration = Duration::from_secs(900);

/// Boxed async resolver: tenant UUID → its [`CapabilityRegistry`]. Production
/// injects the Postgres-backed [`pg_registry_resolver`]; tests inject a mock.
pub type RegistryResolveFn = Arc<
    dyn Fn(Uuid) -> Pin<Box<dyn Future<Output = anyhow::Result<CapabilityRegistry>> + Send>>
        + Send
        + Sync,
>;

/// In-process per-tenant capability-registry cache.
pub struct RegistryLoader {
    cache: Cache<Uuid, Arc<CapabilityRegistry>>,
    /// Last successfully-resolved registry per tenant. Survives the moka TTL so
    /// a store outage preserves each tenant's real posture instead of failing
    /// open to permissive. Only written on a successful resolve.
    last_known: Arc<DashMap<Uuid, Arc<CapabilityRegistry>>>,
    resolve: RegistryResolveFn,
}

impl RegistryLoader {
    #[must_use]
    pub fn new(resolve: RegistryResolveFn) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(MAX_CAPACITY)
                .time_to_live(TTL)
                .build(),
            last_known: Arc::new(DashMap::new()),
            resolve,
        }
    }

    /// Resolve a tenant's capability registry. Warm reads never hit Postgres.
    ///
    /// **Store-outage posture.** On a resolver error we do NOT blindly
    /// return an empty permissive registry (that would silently disable R3/R4
    /// enforcement for a *configured* tenant on a DB blip). Instead we reuse the
    /// tenant's last-known registry if we have one (posture preserved). With no
    /// last-known (cold + store down) we fall back to **PERMISSIVE** (available),
    /// not enforcing — failing a cold/unconfigured tenant closed would turn a DB
    /// blip into 403s on agentic traffic for any R4-entitled tenant. See the
    /// module docs for the full rationale.
    pub async fn resolve(&self, tenant: Uuid) -> Arc<CapabilityRegistry> {
        if let Some(reg) = self.cache.get(&tenant).await {
            return reg;
        }
        let reg = match (self.resolve)(tenant).await {
            Ok(r) => {
                let arc = Arc::new(r);
                self.last_known.insert(tenant, arc.clone());
                arc
            }
            Err(err) => match self.last_known.get(&tenant) {
                Some(known) => {
                    tracing::warn!(
                        error = %err,
                        tenant = %tenant,
                        posture = known.posture().as_str(),
                        "tool-capability registry load failed — reusing last-known registry (posture preserved, fail-closed)"
                    );
                    known.value().clone()
                }
                None => {
                    tracing::warn!(
                        error = %err,
                        tenant = %tenant,
                        "tool-capability registry load failed with no last-known — falling back to PERMISSIVE (cold; a configured tenant is preserved via last_known, so this cannot silently disable an enforcing tenant)"
                    );
                    Arc::new(CapabilityRegistry::new())
                }
            },
        };
        self.cache.insert(tenant, reg.clone()).await;
        reg
    }

    /// Evict a tenant's cached registry (call on a registration change). Only
    /// evicts the short-TTL cache — the last-known store is preserved so a
    /// store outage right after an invalidation still fails closed to the real
    /// posture, not permissive.
    pub async fn invalidate(&self, tenant: Uuid) {
        self.cache.invalidate(&tenant).await;
    }
}

/// Postgres-backed resolver: load a tenant's `tool_capabilities` rows into a
/// registry. Zero rows → empty (permissive). Tenant isolation: `WHERE
/// tenant_id = $1` from the resolved UUID, never an org_id.
#[must_use]
pub fn pg_registry_resolver(pool: crate::db::DbPool) -> RegistryResolveFn {
    Arc::new(move |tenant: Uuid| {
        let pool = pool.clone();
        Box::pin(async move {
            let client = pool
                .get()
                .await
                .map_err(|e| anyhow::anyhow!("registry pool: {e}"))?;
            const SQL: &str =
                "SELECT tool_name, caps, def_hash FROM tool_capabilities WHERE tenant_id = $1";
            let rows = client.query(SQL, &[&tenant]).await?;
            let mut reg = CapabilityRegistry::new();
            for row in &rows {
                let name: String = row.get(0);
                let caps_raw: i16 = row.get(1);
                let pinned_hex: Option<String> = row.get(2);
                let caps = CapabilitySet::from_bits_truncate(u8::try_from(caps_raw).unwrap_or(0));
                // Pin the approved def_hash when present + parseable; a malformed
                // hash degrades to caps-only (logged) rather than failing the load.
                match pinned_hex.as_deref().map(blake3::Hash::from_hex) {
                    Some(Ok(hash)) => reg.register_pinned(name, caps, hash),
                    Some(Err(err)) => {
                        tracing::warn!(error = %err, "tool_capabilities.def_hash unparseable — registering caps-only");
                        reg.register(name, caps);
                    }
                    None => reg.register(name, caps),
                }
            }
            Ok(reg)
        }) as Pin<Box<dyn Future<Output = anyhow::Result<CapabilityRegistry>> + Send>>
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::RegistryPosture;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn resolves_tools_and_caches() {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let loader = RegistryLoader::new(Arc::new(move |_tenant| {
            let c = c.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::SeqCst);
                let mut reg = CapabilityRegistry::new();
                reg.register("send_email", CapabilitySet::CAN_EXFILTRATE);
                Ok(reg)
            })
        }));
        let tenant = Uuid::from_u128(1);

        let reg = loader.resolve(tenant).await;
        assert_eq!(
            reg.posture(),
            RegistryPosture::Enforcing,
            "non-empty → enforcing"
        );
        assert_eq!(
            reg.resolve("send_email").effective(),
            CapabilitySet::CAN_EXFILTRATE
        );

        // Warm cache → no re-resolve.
        let _again = loader.resolve(tenant).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Invalidate → re-resolves.
        loader.invalidate(tenant).await;
        let _third = loader.resolve(tenant).await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn empty_tenant_is_permissive() {
        let loader = RegistryLoader::new(Arc::new(|_tenant| {
            Box::pin(async { Ok(CapabilityRegistry::new()) })
        }));
        let reg = loader.resolve(Uuid::from_u128(2)).await;
        assert_eq!(reg.posture(), RegistryPosture::Permissive);
    }

    #[tokio::test]
    async fn resolver_outage_cold_falls_back_to_permissive() {
        // A store outage with NO last-known registry falls back to
        // PERMISSIVE (available), NOT enforcing. Failing a cold/unconfigured
        // tenant closed would turn a DB blip into 403s on agentic traffic for any
        // R4-entitled tenant (under enforcing, untagged tools → all-caps → R4
        // blocks a converged trifecta). The fail-open a *configured* tenant cared
        // about is covered by last_known (next test).
        let loader = RegistryLoader::new(Arc::new(|_tenant| {
            Box::pin(async { anyhow::bail!("postgres unreachable") })
        }));
        let reg = loader.resolve(Uuid::from_u128(3)).await;
        assert_eq!(
            reg.posture(),
            RegistryPosture::Permissive,
            "cold store outage falls back to permissive (available) — a blip must not 403 agentic traffic"
        );
        assert!(
            !reg.resolve("mystery_tool").is_enforced_unknown(),
            "untagged tool under a cold permissive fallback → not fail-closed (no all-caps)"
        );
    }

    #[tokio::test]
    async fn resolver_outage_preserves_last_known_enforcing() {
        // An ENFORCING tenant that was loaded once must KEEP its enforcing
        // posture through a later store outage — never drop to permissive.
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let loader = RegistryLoader::new(Arc::new(move |_tenant| {
            let c = c.clone();
            Box::pin(async move {
                // First call succeeds (enforcing tenant); every later call errors.
                if c.fetch_add(1, Ordering::SeqCst) == 0 {
                    let mut reg = CapabilityRegistry::new();
                    reg.register("send_email", CapabilitySet::CAN_EXFILTRATE);
                    Ok(reg)
                } else {
                    anyhow::bail!("postgres unreachable")
                }
            })
        }));
        let tenant = Uuid::from_u128(4);

        // Warm load → enforcing, stored in last_known.
        let first = loader.resolve(tenant).await;
        assert_eq!(first.posture(), RegistryPosture::Enforcing);

        // Evict the short-TTL cache; last_known persists. Next resolve hits the
        // (now-erroring) resolver and must reuse the last-known enforcing registry.
        loader.invalidate(tenant).await;
        let after_outage = loader.resolve(tenant).await;
        assert_eq!(
            after_outage.posture(),
            RegistryPosture::Enforcing,
            "outage after a successful load must preserve the enforcing posture, not fail open"
        );
        assert_eq!(
            after_outage.resolve("send_email").effective(),
            CapabilitySet::CAN_EXFILTRATE,
            "last-known caps preserved through the outage"
        );
    }
}
