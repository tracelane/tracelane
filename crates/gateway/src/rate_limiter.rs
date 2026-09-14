//! Per-tenant token-bucket rate limiter (BILL-01 / ADR-076).
//!
//! In-process DashMap implementation for single-node V1. Redis-backed
//! multi-node version is V1.5 (Upstash Redis via deadpool).
//!
//! **BILL-01 deleted the trace-count monthly quota and the `RateLimitTier`
//! enum entirely** (ADR-076 supersedes ADR-020's ladder). There is no more
//! "plan tier" as a rate-limiting concept: the limiter takes a plain
//! `Option<u32>` requests-per-minute figure straight from
//! `ResolvedEntitlements.rate_limit_rpm` (`plan_entitlements.rate_limit_rpm`,
//! overlaid by a `workspace_entitlements` override) — `None` means unlimited,
//! which is what Enterprise, the bench grant, and a self-hosted gateway with
//! no declared cap all resolve to. `RateLimitTier::from_plan_tier_str` and its
//! four siblings (`clickhouse_query.rs`'s `PlanTier::from_plan_key` is a
//! DIFFERENT, unrelated enum — see that file's module doc — and stays) were a
//! parallel, hardcoded mirror of the same number the entitlement cache
//! already resolves; keeping both was the drift SRE register #20 kept
//! finding.
//!
//! Enterprise is always-allow on RPM (via `rate_limit_rpm: None`).

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::instrument;

use tracelane_shared::TenantId;

/// The rate-limit RPM a request resolves to when there is **NO control
/// plane** (`state.entitlements` is `None` — dev, or an OSS self-host with no
/// Postgres). Hosted deployments never reach this: they always have a control
/// plane, so `state.entitlements` is `Some` and `ResolvedEntitlements
/// .rate_limit_rpm` is what governs.
///
/// **B-357/F8, 2026-09-07, preserved under BILL-01:** a self-hosted gateway
/// defaults to UNLIMITED (`None`) — the operator owns the compute, and the
/// hosted Free tier's RPM figure exists to meter OUR plans, not to throttle
/// someone's own box. A hosted-but-poolless process (should not happen in
/// practice) still gets the conservative Free-equivalent 60 rpm, fail-
/// restricted.
///
/// **The `TRACELANE_SELF_HOST_TIER` operator override is REMOVED with the
/// tier concept itself (ADR-076).** There is no named tier left to declare;
/// a self-hoster who wants a cap sets one on their own reverse proxy. Read
/// ONCE, at boot, into `AppState::no_control_plane_rate_limit_rpm` (mirrors
/// B-386 b's `no_control_plane_tier` pattern). `# Errors`: none — fail-CLOSED
/// (the conservative 60 rpm) on any doubt, i.e. whenever self-host cannot be
/// confirmed.
#[must_use]
pub fn no_control_plane_rate_limit_rpm_from_env() -> Option<u32> {
    let self_host = matches!(tracelane_shared::self_host::from_env(), Ok(Some(_)));
    resolve_no_control_plane_rate_limit_rpm(self_host)
}

/// Pure half of [`no_control_plane_rate_limit_rpm_from_env`] so the rule is
/// unit-testable without env mutation.
#[must_use]
pub(crate) const fn resolve_no_control_plane_rate_limit_rpm(self_host: bool) -> Option<u32> {
    if self_host { None } else { Some(60) }
}

/// Single token bucket. `pub(crate)` so the WorkOS webhook ingress limiter
/// (`auth::workos_webhook::WebhookRateLimiter`) reuses the exact same
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
/// Each entry is keyed by `(tenant_id_string, bucket_kind)` so the tenant
/// bucket and a key's own override bucket (GWY-43) never collide.
///
/// Thread-safe: DashMap uses fine-grained shard locking.
/// Bucket discriminant for the TENANT bucket.
const TENANT_BUCKET: u8 = 0;
/// Bucket discriminant for the PER-KEY bucket (GWY-43). Distinct from
/// [`TENANT_BUCKET`] so a key's own override never shares state with its
/// tenant's platform bucket.
const KEY_BUCKET: u8 = 255;

pub struct RateLimiter {
    buckets: Arc<DashMap<(String, u8), BucketState>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Check whether `tenant_id` is within `rpm` requests/minute.
    ///
    /// `rpm` of `None` means unlimited (Enterprise, bench, or a self-hosted
    /// gateway with no declared cap) and short-circuits before touching the
    /// bucket map at all — the same MECHANISM the old `RateLimitTier::Bench`
    /// short-circuit proved matters (B-187c): a huge-but-finite capacity on
    /// the float bucket path is NOT the same as unlimited under a k6-scale
    /// burst.
    #[instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub fn check(&self, tenant_id: &TenantId, rpm: Option<u32>) -> RateLimitDecision {
        self.check_scoped(tenant_id, rpm, None, None)
    }

    /// Check a request against a **per-key** RPM cap, falling back to the
    /// tenant's own `rpm` when the key has none (GWY-43).
    ///
    /// Two separate buckets, and the request must pass BOTH:
    ///
    ///   - the **tenant** bucket, keyed `(tenant_id, TENANT_BUCKET)` —
    ///     unchanged, and the one that protects the platform;
    ///   - the **key** bucket, keyed `(tenant_id + key_id, KEY_BUCKET)` — a
    ///     customer's own ceiling on one credential, so a runaway script
    ///     holding one key cannot consume the whole workspace's allowance.
    ///
    /// `key_rpm` of `None` — no override configured — leaves behaviour exactly
    /// as it was before GWY-43. The tenant check still runs first, so an
    /// unlimited (`rpm: None`) tenant short-circuits for keys without an
    /// override too.
    #[instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub fn check_scoped(
        &self,
        tenant_id: &TenantId,
        rpm: Option<u32>,
        key_id: Option<&str>,
        key_rpm: Option<u32>,
    ) -> RateLimitDecision {
        let tenant_decision = self.check_tenant(tenant_id, rpm);
        if matches!(tenant_decision, RateLimitDecision::Throttle { .. }) {
            return tenant_decision;
        }
        // A per-key cap is a customer's own ceiling and applies even on a
        // tenant with no platform-level cap — an Enterprise workspace that
        // sets a 10 rpm cap on a CI key means it.
        match (key_id, key_rpm) {
            (Some(id), Some(rpm)) if rpm > 0 => {
                self.consume(format!("{tenant_id}/{id}"), KEY_BUCKET, f64::from(rpm))
            }
            _ => tenant_decision,
        }
    }

    fn check_tenant(&self, tenant_id: &TenantId, rpm: Option<u32>) -> RateLimitDecision {
        let Some(rpm) = rpm else {
            return RateLimitDecision::Allow;
        };
        self.consume(tenant_id.to_string(), TENANT_BUCKET, f64::from(rpm))
    }

    fn consume(&self, bucket_id: String, bucket_kind: u8, rpm: f64) -> RateLimitDecision {
        let capacity = rpm;
        // Tokens refilled at rpm/60_000 per millisecond (= rpm per minute)
        let refill_per_ms = rpm / 60_000.0;
        let key = (bucket_id, bucket_kind);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_control_plane_rpm_is_60_unless_self_host() {
        assert_eq!(resolve_no_control_plane_rate_limit_rpm(false), Some(60));
        // F8/B-357: self-host with no declared cap is UNLIMITED.
        assert_eq!(resolve_no_control_plane_rate_limit_rpm(true), None);
    }

    // ── GWY-43: per-key rate limits ─────────────────────────────────────────

    fn t() -> TenantId {
        TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xA11CE))
    }

    /// The control, OBSERVED THROTTLING. A per-key cap that has never been seen
    /// to refuse is not a cap.
    #[test]
    fn a_per_key_cap_throttles_that_key() {
        let rl = RateLimiter::new();
        let tenant = t();
        // The tenant is unlimited; the KEY cap is 3.
        let mut allowed = 0;
        for _ in 0..10 {
            if matches!(
                rl.check_scoped(&tenant, None, Some("key-a"), Some(3)),
                RateLimitDecision::Allow
            ) {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 3,
            "a 3 rpm key cap must allow exactly 3 in a burst"
        );
    }

    /// The isolation property: one key exhausting its cap must not throttle a
    /// DIFFERENT key on the same tenant. Without this the feature is just a
    /// second tenant limit wearing a key's name.
    #[test]
    fn one_keys_cap_does_not_throttle_another_key() {
        let rl = RateLimiter::new();
        let tenant = t();
        for _ in 0..5 {
            let _ = rl.check_scoped(&tenant, None, Some("key-a"), Some(2));
        }
        assert!(
            matches!(
                rl.check_scoped(&tenant, None, Some("key-a"), Some(2)),
                RateLimitDecision::Throttle { .. }
            ),
            "key-a must be exhausted"
        );
        assert!(
            matches!(
                rl.check_scoped(&tenant, None, Some("key-b"), Some(2)),
                RateLimitDecision::Allow
            ),
            "key-b has its own bucket and must still pass"
        );
    }

    /// No override = exactly the pre-GWY-43 behaviour. This is the regression
    /// guard for every key that exists today.
    #[test]
    fn no_override_behaves_exactly_like_the_tenant_check() {
        let rl = RateLimiter::new();
        let tenant = t();
        for _ in 0..50 {
            assert_eq!(
                rl.check_scoped(&tenant, None, Some("key-a"), None),
                RateLimitDecision::Allow,
                "a key with no override must not be limited more than its (unlimited) tenant"
            );
        }
    }

    /// A per-key cap applies even where the platform bucket short-circuits. An
    /// unlimited (`rpm: None`) workspace that puts a 2 rpm cap on a CI key
    /// means it.
    #[test]
    fn a_key_cap_binds_even_on_an_unlimited_tenant() {
        let rl = RateLimiter::new();
        let tenant = t();
        let mut allowed = 0;
        for _ in 0..6 {
            if matches!(
                rl.check_scoped(&tenant, None, Some("ci"), Some(2)),
                RateLimitDecision::Allow
            ) {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 2,
            "the customer's own cap is not waived by an unlimited platform tier"
        );
    }

    /// The tenant bucket is still checked FIRST, so a per-key cap cannot be used
    /// to escape the platform's own limit.
    #[test]
    fn a_generous_key_cap_cannot_exceed_the_tenant_limit() {
        let rl = RateLimiter::new();
        let tenant = t();
        let cap = 60u32;
        let mut allowed = 0;
        for _ in 0..(cap + 20) {
            if matches!(
                rl.check_scoped(&tenant, Some(cap), Some("k"), Some(u32::MAX)),
                RateLimitDecision::Allow
            ) {
                allowed += 1;
            }
        }
        assert!(
            allowed <= cap,
            "allowed {allowed} > tenant cap {cap}: a key override must not widen the platform limit"
        );
    }

    #[test]
    fn key_bucket_discriminant_cannot_collide_with_tenant_bucket() {
        assert_ne!(TENANT_BUCKET, KEY_BUCKET);
    }

    fn tid(s: &str) -> TenantId {
        TenantId::from_jwt_claim(uuid::Uuid::parse_str(s).unwrap_or_else(|_| uuid::Uuid::new_v4()))
    }

    /// B-187c, ported: `None` (unlimited) must never throttle, and it must do
    /// so by SHORT-CIRCUITING before the bucket map, not by sitting under a
    /// huge-but-finite capacity — the same discriminating-mechanism test the
    /// old `RateLimitTier::Bench` had.
    #[test]
    fn unlimited_rpm_is_never_throttled_and_never_touches_the_bucket_map() {
        let rl = RateLimiter::new();
        let t = TenantId::from_jwt_claim(uuid::Uuid::nil());
        for i in 0..1_000u32 {
            assert_eq!(
                rl.check(&t, None),
                RateLimitDecision::Allow,
                "unlimited rpm throttled at request {i}"
            );
        }
        assert!(
            rl.buckets.is_empty(),
            "an unlimited rpm created a rate-limit bucket — it is going through the \
             token-bucket path instead of short-circuiting, so it is NOT actually unlimited"
        );
        // Discriminating control: the same limiter DOES throttle a finite rpm,
        // so the assertion above is not passing because throttling is broken
        // entirely.
        let f = TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
        let mut throttled = false;
        for _ in 0..200 {
            if rl.check(&f, Some(60)) != RateLimitDecision::Allow {
                throttled = true;
                break;
            }
        }
        assert!(
            throttled,
            "a finite rpm never throttled — the control is vacuous"
        );
    }

    #[test]
    fn finite_rpm_allows_up_to_the_configured_rate() {
        let rl = RateLimiter::new();
        let t = tid("00000000-0000-0000-0000-000000000001");
        // First 60 requests should all pass (bucket starts full)
        for _ in 0..60 {
            assert_eq!(rl.check(&t, Some(60)), RateLimitDecision::Allow);
        }
        // 61st should throttle
        assert!(matches!(
            rl.check(&t, Some(60)),
            RateLimitDecision::Throttle { .. }
        ));
    }

    #[test]
    fn different_tenants_have_independent_buckets() {
        let rl = RateLimiter::new();
        let t1 = tid("00000000-0000-0000-0000-000000000003");
        let t2 = tid("00000000-0000-0000-0000-000000000004");
        // Drain t1's bucket
        for _ in 0..60 {
            rl.check(&t1, Some(60));
        }
        // t2 should still have a full bucket
        assert_eq!(rl.check(&t2, Some(60)), RateLimitDecision::Allow);
    }

    #[test]
    fn throttle_returns_positive_retry_after() {
        let rl = RateLimiter::new();
        let t = tid("00000000-0000-0000-0000-000000000005");
        // Drain bucket
        for _ in 0..60 {
            rl.check(&t, Some(60));
        }
        match rl.check(&t, Some(60)) {
            RateLimitDecision::Throttle { retry_after_secs } => {
                assert!(
                    retry_after_secs >= 1,
                    "retry_after must be at least 1 second"
                );
            }
            RateLimitDecision::Allow => panic!("expected throttle"),
        }
    }
}
