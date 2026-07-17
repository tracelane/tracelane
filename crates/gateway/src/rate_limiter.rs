//! Per-tenant token-bucket rate limiter + monthly quota tracker.
//!
//! In-process DashMap implementation for single-node V1. Redis-backed
//! multi-node version is V1.5 (Upstash Redis via deadpool).
//!
//! Two independent layers:
//!   - `RateLimiter`  — RPM token bucket (short-window burst control).
//!   - `QuotaTracker` — monthly trace counter with hard 5× cap.
//!
//! Enterprise is always-allow on RPM.
//! Quota config is supplied by the caller (read from the cached
//! `workspace_entitlements` row), never fetched inside the hot path —
//! hot-path budget is single atomic load + compare (<500ns p99).

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::instrument;

use tracelane_shared::TenantId;

/// Per-tenant rate limit tiers (requests per minute).
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum RateLimitTier {
    Free = 0,
    Builder = 1,
    Team = 2,
    Business = 3,
    Enterprise = 4,
}

impl RateLimitTier {
    /// RPM limits per tier.
    pub fn requests_per_minute(self) -> u32 {
        match self {
            Self::Free => 60,
            Self::Builder => 600,
            Self::Team => 6_000,
            Self::Business => 60_000,
            Self::Enterprise => u32::MAX,
        }
    }

    /// Parse the tier from the string Polar stores in `tenants.plan_tier`
    /// (lowercase, single word). Anything unknown falls back to Free —
    /// fail-restricted is the safe default for an unrecognized plan
    /// string, never grant higher limits than we billed for.
    pub fn from_plan_tier_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "builder" => Self::Builder,
            "team" => Self::Team,
            "business" => Self::Business,
            "enterprise" => Self::Enterprise,
            // "free" and anything else
            _ => Self::Free,
        }
    }
}

/// Single token bucket. `pub(crate)` so the WorkOS webhook ingress limiter
/// refill/consume math instead of hand-rolling a second copy.
pub(crate) struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl BucketState {
    pub(crate) fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    ///
    /// Returns `true` if a token was consumed (request allowed).
    pub(crate) fn try_consume(&mut self, capacity: f64, refill_per_ms: f64) -> bool {
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.last_refill).as_secs_f64() * 1000.0;
        self.tokens = (self.tokens + elapsed_ms * refill_per_ms).min(capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Seconds until at least one token is available (ceiling).
    pub(crate) fn retry_after_secs(&self, refill_per_ms: f64) -> u32 {
        let deficit = 1.0 - self.tokens;
        let ms_needed = deficit / refill_per_ms;
        (ms_needed / 1000.0).ceil() as u32
    }
}

/// Token-bucket rate limiter backed by an in-process DashMap.
///
/// Each entry is keyed by `(tenant_id_string, tier_discriminant)` so
/// different tiers for the same tenant get independent buckets. In practice
/// we always call with one tier per tenant; the u8 key prevents future
/// collision if multiple tiers are checked.
///
/// Thread-safe: DashMap uses fine-grained shard locking.
pub struct RateLimiter {
    buckets: Arc<DashMap<(String, u8), BucketState>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Check whether `tenant_id` is within the RPM cap for `tier`.
    ///
    /// Returns `Allow` immediately for Enterprise (no bucket needed).
    /// Returns `Throttle { retry_after_secs }` when the bucket is empty.
    #[instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub fn check(&self, tenant_id: &TenantId, tier: RateLimitTier) -> RateLimitDecision {
        if matches!(tier, RateLimitTier::Enterprise) {
            return RateLimitDecision::Allow;
        }

        let rpm = f64::from(tier.requests_per_minute());
        let capacity = rpm;
        // Tokens refilled at rpm/60_000 per millisecond (= rpm per minute)
        let refill_per_ms = rpm / 60_000.0;
        let tier_key = tier as u8;
        let key = (tenant_id.to_string(), tier_key);

        let mut entry = self
            .buckets
            .entry(key)
            .or_insert_with(|| BucketState::new(capacity));

        if entry.try_consume(capacity, refill_per_ms) {
            RateLimitDecision::Allow
        } else {
            RateLimitDecision::Throttle {
                retry_after_secs: entry.retry_after_secs(refill_per_ms).max(1),
            }
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allow,
    /// Retry-After in seconds.
    Throttle {
        retry_after_secs: u32,
    },
}

// ---------------------------------------------------------------------------
// QuotaTracker — monthly trace counter with hard 5× cap
// ---------------------------------------------------------------------------

/// Per-tenant monthly quota configuration. Sourced from `workspace_entitlements`
/// (deny-overrides-grant) with fallback to `plan_entitlements` defaults.
///
/// Copy semantics so the hot-path call site holds it by value without
/// touching DashMap; refresh is done out-of-band by the entitlements cache.
#[derive(Debug, Clone, Copy)]
pub struct QuotaConfig {
    /// Monthly included quota — e.g. 150_000 for Builder. 0 means "no quota
    /// enforced" (only the OSS self-host path passes 0; hosted plans always
    /// have a positive quota, even Free at 10_000).
    pub trace_quota_monthly: u64,
    /// Hard-cap multiplier on the included quota. 5.0 for paid plans →
    /// usage > quota*5 returns 429. Stored as integer tenths so the hot
    /// path stays integer-only (5.0 → 50).
    pub hard_cap_tenths: u32,
}

impl QuotaConfig {
    /// Returns the absolute hard-cap usage value above which requests are
    /// rejected with 429. Saturates on overflow (caller treats saturation
    /// as "no cap" — only triggers at Enterprise quota * 99× ≈ 2.5e12).
    #[inline]
    pub fn hard_cap_absolute(&self) -> u64 {
        self.trace_quota_monthly
            .saturating_mul(u64::from(self.hard_cap_tenths))
            / 10
    }

    /// Map the `tenants.plan_tier` string to a QuotaConfig.
    ///
    /// Values mirror the `plan_entitlements` seed rows (`apps/web/db/seed.mjs`;
    /// in-memory fallback for
    /// the gateway hot path; the dashboard reads the same values through
    /// `plan_entitlements` + `workspace_entitlements` (deny-overrides-grant).
    /// Drift between the two is a bug — keep them synchronised with the
    /// entitlement seed rows (the authoritative numbers).
    ///
    /// Anything unknown falls back to Free quota (10K/mo) — fail-restricted
    /// for the same reason `RateLimitTier::from_plan_tier_str` does.
    pub fn from_plan_tier_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "builder" => Self {
                trace_quota_monthly: 150_000,
                hard_cap_tenths: 50, // 5.0×
            },
            "team" => Self {
                trace_quota_monthly: 1_000_000,
                hard_cap_tenths: 50,
            },
            "business" => Self {
                trace_quota_monthly: 5_000_000,
                hard_cap_tenths: 50,
            },
            "enterprise" => Self {
                trace_quota_monthly: 25_000_000,
                hard_cap_tenths: 990, // 99.0× — effectively unlimited
            },
            // "free" and anything else
            _ => Self {
                trace_quota_monthly: 10_000,
                hard_cap_tenths: 10, // 1.0× — Free has no overage allowed
            },
        }
    }
}

/// Decision returned by `QuotaTracker::check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Within the included monthly quota.
    Allow,
    /// Above the included quota, below the hard cap — billable overage.
    /// Caller meters this to Polar via `overage_v1` lookup_key.
    AllowWithOverage,
    /// Above `quota * hard_cap_tenths/10`. Caller must return 429 +
    /// the structured body `{error,limit,used,reset_at,upgrade_url}` and
    /// fire-and-forget the Slack webhook POST.
    HardCapExceeded { limit: u64, used: u64 },
}

/// Tracks monthly trace usage per tenant with sub-microsecond decision overhead.
///
/// Storage: `DashMap<TenantId, AtomicU64>` — the AtomicU64 is the only state
/// touched on the request hot path. DashMap entry lookup is the dominant cost;
/// once the entry exists it's a single relaxed `fetch_add` + compare.
///
/// Reset: callers are expected to swap counters at month boundary via
/// `reset_for_period(tenant_id)`. The 60s entitlements cache refresh is the
/// usual trigger; the month boundary is a once-a-month batch elsewhere.
pub struct QuotaTracker {
    /// Per-tenant atomic monthly usage counter.
    ///
    /// `String` key (TenantId serialised) so we don't depend on TenantId
    /// implementing `Hash + Eq` (it currently does, but keeping this
    /// loose mirrors the existing RateLimiter pattern).
    usage: Arc<DashMap<String, AtomicU64>>,
    /// B-109 durability: per-tenant `YYYYMM` the in-memory counter was last
    /// seeded from the durable ClickHouse trace count for. Empty = never seeded
    /// this process (fresh start / post-deploy). Drives both restart-durability
    /// (re-seed after a restart) and the month-boundary reset (`reset_for_period`
    /// was never wired up); see `needs_seed` / `seed_if_needed`.
    seeded: Arc<DashMap<String, u32>>,
}

impl QuotaTracker {
    pub fn new() -> Self {
        Self {
            usage: Arc::new(DashMap::new()),
            seeded: Arc::new(DashMap::new()),
        }
    }

    /// Increment the monthly counter by 1 and return the decision.
    ///
    /// Hot-path budget: <500ns p99. Implementation is a single DashMap
    /// entry lookup + atomic `fetch_add(1, Relaxed)` + two integer compares.
    /// No locks held across the comparison. `Relaxed` ordering is correct:
    /// the counter is only ever read for billing/decision purposes, never
    /// used to synchronise other memory.
    #[instrument(skip(self, config), fields(tenant_id = %tenant_id))]
    pub fn check(&self, tenant_id: &TenantId, config: QuotaConfig) -> QuotaDecision {
        if config.trace_quota_monthly == 0 {
            return QuotaDecision::Allow;
        }
        // Bypass the DashMap entirely on the hot-cap fast path: a single
        // atomic load if the entry already exists.
        let key = tenant_id.to_string();
        let counter = self.usage.entry(key).or_insert_with(|| AtomicU64::new(0));
        let used = counter.fetch_add(1, Ordering::Relaxed) + 1;
        let limit = config.hard_cap_absolute();
        if used > limit {
            QuotaDecision::HardCapExceeded { limit, used }
        } else if used > config.trace_quota_monthly {
            QuotaDecision::AllowWithOverage
        } else {
            QuotaDecision::Allow
        }
    }

    /// Read current monthly usage without incrementing. For status endpoints
    /// and the 429 response body. Returns 0 for tenants with no recorded usage.
    pub fn current_usage(&self, tenant_id: &TenantId) -> u64 {
        let key = tenant_id.to_string();
        self.usage
            .get(&key)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Reset the monthly counter for a tenant. Called at month boundary
    /// by the billing reconciler (not on the hot path).
    pub fn reset_for_period(&self, tenant_id: &TenantId) {
        let key = tenant_id.to_string();
        if let Some(counter) = self.usage.get(&key) {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// B-109 durability: does this tenant's counter need (re)seeding for
    /// `year_month` (`YYYYMM`)? True if never seeded this process (post-restart)
    /// or last seeded for a different month (month boundary). The hot path calls
    /// this FIRST so the durable ClickHouse baseline read happens once per tenant
    /// per month per process, never per request (warm path stays allocation-free
    /// past this cheap map probe).
    pub fn needs_seed(&self, tenant_id: &TenantId, year_month: u32) -> bool {
        let key = tenant_id.to_string();
        self.seeded
            .get(&key)
            .map(|m| *m != year_month)
            .unwrap_or(true)
    }

    /// B-109 durability: seed the in-memory monthly counter from a durable
    /// `baseline` (the ClickHouse trace count for `year_month`) so a restart or
    /// blue-green deploy no longer forgives accrued usage — the pre-B-109 counter
    /// silently reset to 0 on every restart, making the hard cap bypassable by a
    /// redeploy.
    ///
    /// Race-safe + idempotent: the `seeded` entry is the guard, so concurrent
    /// first-requests for the same tenant seed exactly once. A caller that finds
    /// the current month already recorded skips (returns `false`) and never
    /// clobbers increments that the first seed's requests already made. The month
    /// is part of the guard, so the first request of a new calendar month
    /// re-seeds from the reset monthly count — the boundary reset `reset_for_period`
    /// never wired up. Returns whether it actually seeded.
    pub fn seed_if_needed(&self, tenant_id: &TenantId, year_month: u32, baseline: u64) -> bool {
        use dashmap::mapref::entry::Entry;
        let key = tenant_id.to_string();
        match self.seeded.entry(key.clone()) {
            // Already seeded for this month — do NOT re-store (would clobber the
            // live increments made since the first seed).
            Entry::Occupied(e) if *e.get() == year_month => false,
            Entry::Occupied(mut e) => {
                self.store_baseline(&key, baseline);
                e.insert(year_month);
                true
            }
            Entry::Vacant(v) => {
                self.store_baseline(&key, baseline);
                v.insert(year_month);
                true
            }
        }
    }

    /// Overwrite a tenant's counter with `baseline` (the durable rehydration
    /// value). Only called from `seed_if_needed` under the `seeded`-entry guard.
    fn store_baseline(&self, key: &str, baseline: u64) {
        self.usage
            .entry(key.to_string())
            .and_modify(|c| c.store(baseline, Ordering::Relaxed))
            .or_insert_with(|| AtomicU64::new(baseline));
    }
}

impl Default for QuotaTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::TenantId;

    fn tid(s: &str) -> TenantId {
        TenantId::from_jwt_claim(uuid::Uuid::parse_str(s).unwrap_or_else(|_| uuid::Uuid::new_v4()))
    }

    /// A5 revenue-leak guard (2026-07-10): a freshly-provisioned tenant is plan
    /// "free" (the WorkOS webhook provisions "free"; `tenants.plan` DEFAULT
    /// 'free'). That MUST resolve to the 10K free quota — never the 150K Builder
    /// quota (the leak was fresh signups landing on Builder). Unknown/blank plan
    /// strings are ALSO free-quota (fail-restricted).
    #[test]
    fn fresh_signup_resolves_to_free_quota_not_builder() {
        let fresh = QuotaConfig::from_plan_tier_str("free");
        assert_eq!(fresh.trace_quota_monthly, 10_000, "free = 10K, not 150K");
        assert_eq!(fresh.hard_cap_tenths, 10, "free = no overage (1.0x)");

        // A NULL/blank/unrecognized plan column must also fail-restricted to free.
        for s in ["", "  ", "bogus", "BUILDER_TYPO"] {
            assert_eq!(
                QuotaConfig::from_plan_tier_str(s).trace_quota_monthly,
                10_000,
                "unrecognized plan {s:?} must fall back to free quota, not Builder",
            );
        }

        // Builder is the paid 150K tier — prove the two are distinct so a
        // regression that maps free/unknown → Builder fails loudly here.
        assert_eq!(
            QuotaConfig::from_plan_tier_str("builder").trace_quota_monthly,
            150_000,
        );
        assert_ne!(fresh.trace_quota_monthly, 150_000);

        // The RPM tier is fail-restricted the same way.
        assert!(matches!(
            RateLimitTier::from_plan_tier_str("free"),
            RateLimitTier::Free
        ));
        assert!(matches!(
            RateLimitTier::from_plan_tier_str("nonsense"),
            RateLimitTier::Free
        ));
    }

    #[test]
    fn free_tier_allows_up_to_60_rpm() {
        let rl = RateLimiter::new();
        let t = tid("00000000-0000-0000-0000-000000000001");
        // First 60 requests should all pass (bucket starts full)
        for _ in 0..60 {
            assert_eq!(rl.check(&t, RateLimitTier::Free), RateLimitDecision::Allow);
        }
        // 61st should throttle
        assert!(matches!(
            rl.check(&t, RateLimitTier::Free),
            RateLimitDecision::Throttle { .. }
        ));
    }

    #[test]
    fn enterprise_always_allows() {
        let rl = RateLimiter::new();
        let t = tid("00000000-0000-0000-0000-000000000002");
        for _ in 0..10_000 {
            assert_eq!(
                rl.check(&t, RateLimitTier::Enterprise),
                RateLimitDecision::Allow
            );
        }
    }

    #[test]
    fn different_tenants_have_independent_buckets() {
        let rl = RateLimiter::new();
        let t1 = tid("00000000-0000-0000-0000-000000000003");
        let t2 = tid("00000000-0000-0000-0000-000000000004");
        // Drain t1's bucket
        for _ in 0..60 {
            rl.check(&t1, RateLimitTier::Free);
        }
        // t2 should still have a full bucket
        assert_eq!(rl.check(&t2, RateLimitTier::Free), RateLimitDecision::Allow);
    }

    #[test]
    fn throttle_returns_positive_retry_after() {
        let rl = RateLimiter::new();
        let t = tid("00000000-0000-0000-0000-000000000005");
        // Drain bucket
        for _ in 0..60 {
            rl.check(&t, RateLimitTier::Free);
        }
        match rl.check(&t, RateLimitTier::Free) {
            RateLimitDecision::Throttle { retry_after_secs } => {
                assert!(
                    retry_after_secs >= 1,
                    "retry_after must be at least 1 second"
                );
            }
            RateLimitDecision::Allow => panic!("expected throttle"),
        }
    }

    // -----------------------------------------------------------------
    // QuotaTracker tests
    // -----------------------------------------------------------------
    fn builder_cfg() -> QuotaConfig {
        QuotaConfig {
            trace_quota_monthly: 150_000,
            hard_cap_tenths: 50, // 5.0x
        }
    }

    #[test]
    fn quota_allow_within_quota() {
        let q = QuotaTracker::new();
        let t = tid("11111111-0000-0000-0000-000000000001");
        let cfg = builder_cfg();
        assert_eq!(q.check(&t, cfg), QuotaDecision::Allow);
    }

    #[test]
    fn quota_overage_above_quota_below_cap() {
        let q = QuotaTracker::new();
        let t = tid("11111111-0000-0000-0000-000000000002");
        // Bigger-than-test quota would burn a few seconds in a tight loop;
        // drive the counter directly via the public API.
        let cfg = QuotaConfig {
            trace_quota_monthly: 5,
            hard_cap_tenths: 50, // 5×5 = 25
        };
        for _ in 0..5 {
            assert_eq!(q.check(&t, cfg), QuotaDecision::Allow);
        }
        assert_eq!(q.check(&t, cfg), QuotaDecision::AllowWithOverage);
        // Many more overage calls still allowed until 25
        for _ in 0..18 {
            assert_eq!(q.check(&t, cfg), QuotaDecision::AllowWithOverage);
        }
    }

    #[test]
    fn quota_hard_cap_returns_429_signal() {
        let q = QuotaTracker::new();
        let t = tid("11111111-0000-0000-0000-000000000003");
        let cfg = QuotaConfig {
            trace_quota_monthly: 5,
            hard_cap_tenths: 50, // hard cap = 25
        };
        for _ in 0..25 {
            q.check(&t, cfg);
        }
        match q.check(&t, cfg) {
            QuotaDecision::HardCapExceeded { limit, used } => {
                assert_eq!(limit, 25);
                assert_eq!(used, 26);
            }
            other => panic!("expected HardCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn quota_zero_quota_always_allows() {
        let q = QuotaTracker::new();
        let t = tid("11111111-0000-0000-0000-000000000004");
        let cfg = QuotaConfig {
            trace_quota_monthly: 0,
            hard_cap_tenths: 50,
        };
        for _ in 0..100 {
            assert_eq!(q.check(&t, cfg), QuotaDecision::Allow);
        }
    }

    #[test]
    fn quota_reset_for_period_zeroes_counter() {
        let q = QuotaTracker::new();
        let t = tid("11111111-0000-0000-0000-000000000005");
        let cfg = QuotaConfig {
            trace_quota_monthly: 5,
            hard_cap_tenths: 50,
        };
        for _ in 0..10 {
            q.check(&t, cfg);
        }
        assert_eq!(q.current_usage(&t), 10);
        q.reset_for_period(&t);
        assert_eq!(q.current_usage(&t), 0);
        // After reset, next call is back to Allow
        assert_eq!(q.check(&t, cfg), QuotaDecision::Allow);
    }

    #[test]
    fn quota_independent_tenants() {
        let q = QuotaTracker::new();
        let t1 = tid("11111111-0000-0000-0000-000000000006");
        let t2 = tid("11111111-0000-0000-0000-000000000007");
        let cfg = QuotaConfig {
            trace_quota_monthly: 2,
            hard_cap_tenths: 50,
        };
        for _ in 0..10 {
            q.check(&t1, cfg);
        }
        assert!(matches!(
            q.check(&t1, cfg),
            QuotaDecision::HardCapExceeded { .. }
        ));
        assert_eq!(q.check(&t2, cfg), QuotaDecision::Allow);
    }

    /// B-109 regression: the counter is durable across "restart" (re-seeds from a
    /// baseline instead of resetting to 0), race-safe (a redundant same-month seed
    /// does not clobber live increments), and month-aware (a new month re-seeds).
    /// Pre-B-109 the counter zeroed on every restart, making the hard cap
    /// bypassable by a redeploy.
    #[test]
    fn seed_is_durable_race_safe_and_month_aware() {
        let q = QuotaTracker::new();
        let t = tid("11111111-0000-0000-0000-00000000000a");

        // Fresh process: the tenant needs seeding for the current month.
        assert!(q.needs_seed(&t, 202607));
        // Rehydrate from a durable baseline of 900 (e.g. the ClickHouse month
        // count) — this is what a restart re-reads instead of starting at 0.
        assert!(q.seed_if_needed(&t, 202607, 900));
        assert_eq!(
            q.current_usage(&t),
            900,
            "counter rehydrated to the baseline"
        );

        // Already seeded this month: needs_seed is false and a redundant seed must
        // NOT clobber the live counter back down (the concurrent-first-request race).
        assert!(!q.needs_seed(&t, 202607));
        assert!(
            !q.seed_if_needed(&t, 202607, 5),
            "redundant same-month seed no-ops"
        );
        assert_eq!(
            q.current_usage(&t),
            900,
            "redundant seed did not clobber to 5"
        );

        // Increments accrue on top of the durable baseline, so the hard cap trips
        // WITHOUT a restart having forgiven the earlier 900.
        let cfg = QuotaConfig {
            trace_quota_monthly: 1_000,
            hard_cap_tenths: 10, // 1.0× → cap == quota (strict "429 at quota")
        };
        for _ in 0..100 {
            q.check(&t, cfg);
        }
        assert_eq!(q.current_usage(&t), 1_000);
        assert!(
            matches!(q.check(&t, cfg), QuotaDecision::HardCapExceeded { .. }),
            "seeded baseline + increments trips the cap; a redeploy no longer resets it"
        );

        // New calendar month → re-seed from the reset monthly count (0).
        assert!(q.needs_seed(&t, 202608));
        assert!(q.seed_if_needed(&t, 202608, 0));
        assert_eq!(
            q.current_usage(&t),
            0,
            "month boundary re-seeds from the reset count"
        );
        assert_eq!(q.check(&t, cfg), QuotaDecision::Allow);
    }
}
