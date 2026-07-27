//! Per-workspace capability-registry loader (the guardrail spec §2.3).
//! Resolves a tenant's registered tool capabilities (the `tool_capabilities`
//! Postgres table, Migration 13) into an in-process [`CapabilityRegistry`],
//! Moka-cached so warm reads never touch Postgres — mirrors the
//! `entitlement_cache` pattern (ADR-035).
//!
//! Safe-default (founder rule): a tenant with no registered tools resolves to an
//! empty → **permissive** registry (untagged tools hold no caps, not blocked).
//! ≥ 1 row → **enforcing**. A resolver error (store outage) **falls back to
//! permissive** — never block traffic because the registry store is down. This
//! is the prerequisite the founder sequenced before R3, so R3 (definition
//! pinning) and R4 (enforce) run against real registry data, not a stub.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use uuid::Uuid;

use crate::guardrail::capability::{CapabilityRegistry, CapabilitySet};

const MAX_CAPACITY: u64 = 10_000;
const TTL: Duration = Duration::from_secs(30);

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
            resolve,
        }
    }

    /// Resolve a tenant's capability registry. Warm reads never hit Postgres.
    /// On a resolver error (store outage) returns an empty **permissive**
    /// registry — fail-safe: never block traffic because the store is down.
    pub async fn resolve(&self, tenant: Uuid) -> Arc<CapabilityRegistry> {
        if let Some(reg) = self.cache.get(&tenant).await {
            return reg;
        }
        let reg = match (self.resolve)(tenant).await {
            Ok(r) => Arc::new(r),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    tenant = %tenant,
                    "tool-capability registry load failed — falling back to PERMISSIVE (no enforcement)"
                );
                Arc::new(CapabilityRegistry::new())
            }
        };
        self.cache.insert(tenant, reg.clone()).await;
        reg
    }

    /// Evict a tenant's cached registry (call on a registration change).
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
    async fn resolver_outage_falls_back_to_permissive() {
        let loader = RegistryLoader::new(Arc::new(|_tenant| {
            Box::pin(async { anyhow::bail!("postgres unreachable") })
        }));
        let reg = loader.resolve(Uuid::from_u128(3)).await;
        assert_eq!(
            reg.posture(),
            RegistryPosture::Permissive,
            "store outage must NOT block traffic — fall back to permissive"
        );
    }
}
