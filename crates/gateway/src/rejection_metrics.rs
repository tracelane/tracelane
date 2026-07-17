//! Per-tenant gateway rejection counters (rate-limit + monthly-quota 429s).
//!
//! Callers: the two 429 branches in [`crate::server`] increment on rejection;
//! the Gateway-ops read (`/v1/gateway/stats` in [`crate::trace_reads`]) reads
//! the authenticated tenant's totals.
//!
//! Why a counter and not a span: a rate-limit / quota 429 is returned BEFORE any
//! provider dispatch, so there is no request span to carry the signal. Emitting
//! one span per rejected request would write telemetry for exactly the load the
//! limiter is shedding — a DoS amplifier under a flood. Instead each rejection is
//! a single relaxed `fetch_add` on a per-`(tenant, reason)` atomic (no I/O, no
//! allocation past the first insert), read on demand by the stats endpoint.
//!
//! Semantics — **process-lifetime totals**, reset on restart/redeploy, NOT a
//! rolling window. The surface labels them "since gateway start" so the number is
//! never confused with the 24h span-derived metrics beside it. Single gateway
//! instance per node today; a multi-instance fleet would sum per-instance
//! counters (documented, not silently wrong).

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tracelane_shared::TenantId;

/// One tenant's rejection tallies. `Default` gives both counters at 0.
#[derive(Default)]
struct TenantRejections {
    rate_limited: AtomicU64,
    quota_exceeded: AtomicU64,
}

/// Process-global per-tenant rejection registry.
///
/// `String` key mirrors [`crate::rate_limiter::QuotaTracker`] — it avoids
/// depending on `TenantId: Hash + Eq` and keeps the two per-tenant maps keyed
/// identically.
pub struct RejectionRegistry {
    by_tenant: DashMap<String, TenantRejections>,
}

impl RejectionRegistry {
    fn new() -> Self {
        Self {
            by_tenant: DashMap::new(),
        }
    }

    /// Record one rate-limit (token-bucket) 429 for `tenant`.
    pub fn record_rate_limited(&self, tenant: &TenantId) {
        self.by_tenant
            .entry(tenant.to_string())
            .or_default()
            .rate_limited
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one monthly-quota hard-cap 429 for `tenant`.
    pub fn record_quota_exceeded(&self, tenant: &TenantId) {
        self.by_tenant
            .entry(tenant.to_string())
            .or_default()
            .quota_exceeded
            .fetch_add(1, Ordering::Relaxed);
    }

    /// `(rate_limited, quota_exceeded)` process-lifetime totals for `tenant`
    /// (`(0, 0)` if the tenant has never been rejected).
    #[must_use]
    pub fn snapshot(&self, tenant: &TenantId) -> (u64, u64) {
        self.by_tenant
            .get(&tenant.to_string())
            .map(|e| {
                (
                    e.rate_limited.load(Ordering::Relaxed),
                    e.quota_exceeded.load(Ordering::Relaxed),
                )
            })
            .unwrap_or((0, 0))
    }
}

/// The process-global registry (lazily initialised on first use).
#[must_use]
pub fn registry() -> &'static RejectionRegistry {
    static R: LazyLock<RejectionRegistry> = LazyLock::new(RejectionRegistry::new);
    &R
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn tenant(n: u128) -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(n))
    }

    #[test]
    fn snapshot_is_zero_for_unseen_tenant() {
        let reg = RejectionRegistry::new();
        assert_eq!(reg.snapshot(&tenant(0xA1)), (0, 0));
    }

    #[test]
    fn counters_advance_independently_per_reason() {
        let reg = RejectionRegistry::new();
        let t = tenant(0xB2);
        reg.record_rate_limited(&t);
        reg.record_rate_limited(&t);
        reg.record_quota_exceeded(&t);
        assert_eq!(reg.snapshot(&t), (2, 1));
    }

    #[test]
    fn counters_are_isolated_per_tenant() {
        let reg = RejectionRegistry::new();
        let a = tenant(1);
        let b = tenant(2);
        reg.record_rate_limited(&a);
        reg.record_quota_exceeded(&b);
        // Tenant a sees only its own rate-limit; b only its own quota reject.
        assert_eq!(reg.snapshot(&a), (1, 0));
        assert_eq!(reg.snapshot(&b), (0, 1));
    }
}
